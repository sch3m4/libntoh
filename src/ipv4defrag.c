/********************************************************************************
 * Copyright (c) 2012, Chema Garcia                                             *
 * All rights reserved.                                                         *
 *                                                                              *
 * Redistribution and use in source and binary forms, with or                   *
 * without modification, are permitted provided that the following              *
 * conditions are met:                                                          *
 *                                                                              *
 *    * Redistributions of source code must retain the above                    *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer.                                                             *
 *                                                                              *
 *    * Redistributions in binary form must reproduce the above                 *
 *      copyright notice, this list of conditions and the following             *
 *      disclaimer in the documentation and/or other materials provided         *
 *      with the distribution.                                                  *
 *                                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   *
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE    *
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR          *
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF         *
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS     *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN      *
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)      *
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE   *
 * POSSIBILITY OF SUCH DAMAGE.                                                  *
 ********************************************************************************/

#define __FAVOR_BSD
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <libntoh.h>

static ntoh_ipv4_params_t params = { 0 , 0 };

#define NTOH_GET_IPV4_FRAGMENT_OFFSET(offset)	(8*(ntohs(offset)&IP_OFFMASK))
#define IS_SET(a,b)				(a & b)

/** @brief API to get the size of the flows table (max allowed flows) **/
unsigned int ntoh_ipv4_get_size ( pntoh_ipv4_session_t session )
{
	unsigned int ret = 0;

	if ( !session )
		return ret;

	lock_access ( & (session->lock) );
	ret = -1;
	unlock_access ( & (session->lock) );

	return ret;
}

/** @brief API to get a tuple4 **/
unsigned int ntoh_ipv4_get_tuple4 ( struct ip *ip , pntoh_ipv4_tuple4_t tuple )
{
	if ( !ip || !tuple )
		return NTOH_ERROR_PARAMS;

	tuple->destination = ip->ip_dst.s_addr;
	tuple->source = ip->ip_src.s_addr;
	tuple->id = ip->ip_id;
	tuple->protocol = ip->ip_p;

	return NTOH_OK;
}

pntoh_ipv4_flow_t ntoh_ipv4_find_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_tuple4_t tuple4 )
{
	pntoh_ipv4_flow_t ret = 0;

	if ( !params.init || !session || !tuple4 )
		return ret;

	lock_access( &session->lock );

	HASH_FIND(hh, session->flows, tuple4, sizeof(*tuple4), ret);

	unlock_access( &session->lock );

	return ret;
}

pntoh_ipv4_flow_t ntoh_ipv4_new_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_tuple4_t tuple4 , pipv4_dfcallback_t function , void *udata , unsigned int *error)
{
	pntoh_ipv4_flow_t flow = 0;

	if ( error != 0 )
		*error = 0;

	if ( !params.init )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_INIT;
		return flow;
	}

	if ( !session || !tuple4 || !function )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_PARAMS;
		return flow;
	}

	if ( sem_trywait( &session->max_flows ) != 0 )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOSPACE;

		return flow;
	}

	if ( !( flow = (pntoh_ipv4_flow_t) calloc( 1, sizeof(ntoh_ipv4_flow_t) ) ) )
		return flow;

	memcpy( &( flow->ident ), tuple4, sizeof(ntoh_ipv4_tuple4_t) );

	gettimeofday( &flow->last_activ, 0 );
	flow->function = (void*) function;
	flow->udata = udata;

	flow->lock.use = 0;
	pthread_mutex_init ( &flow->lock.mutex , 0 );
	pthread_cond_init ( &flow->lock.pcond , 0 );

	lock_access( &session->lock );

        HASH_ADD(hh, session->flows, ident, sizeof(ntoh_ipv4_tuple4_t), flow);

	unlock_access( &session->lock );

	return flow;
}

/* insert a new fragment */
inline static pntoh_ipv4_fragment_t insert_fragment ( pntoh_ipv4_fragment_t list , pntoh_ipv4_fragment_t frag )
{
	pntoh_ipv4_fragment_t aux = list;

	if ( !aux )
		return frag;

	if ( frag->offset > list->offset )
	{
		frag->next = list;
		return frag;
	}

	/* finds the correct position for the new fragment */
	/// Based on 4.3 BSD, we will give priority to fragments with lower offset to avoid teardrop attack
	for ( ; aux->next != 0 && frag->offset < aux->offset ; aux = aux->next );

	if ( aux->next == 0 )
		aux->next = frag;
	else{
		frag->next = aux->next;
		aux->next = frag;
	}

	return list;
}

inline static unsigned short cksum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for(sum=0; nwords>0; nwords--)
		sum += *buf++;

	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}


/* build the complete datagram from all collected IPv4 fragments */
inline static unsigned char *build_datagram ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t flow )
{
	pntoh_ipv4_fragment_t 	tmp;
	pntoh_ipv4_fragment_t 	fragment;
	struct ip				*iphdr;
	unsigned int			offsethdr;
	unsigned char 			*ret;

	fragment = flow->fragments;
	iphdr = flow->final_iphdr;
	offsethdr = iphdr == 0 ? 0 : 4*iphdr->ip_hl;
	ret = (unsigned char*) calloc ( flow->total + offsethdr , sizeof ( unsigned char ) );

	while ( fragment != 0 )
	{
		memcpy ( &ret[offsethdr + fragment->offset] , fragment->data , fragment->len );
		tmp = fragment;
		fragment = fragment->next;
		free ( tmp->data );
		free ( tmp );
		sem_post ( &session->max_fragments );
	}
	flow->fragments = 0;

	/* fix ip header data */
	if ( offsethdr > 0 )
	{
		memcpy ( ret , iphdr , offsethdr );
		iphdr = (struct ip*)ret;
		iphdr->ip_len = htons(flow->total);
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum ( (unsigned short*) iphdr , (int)offsethdr );
		free ( flow->final_iphdr );

		flow->meat += offsethdr;
		flow->total += offsethdr;
	}

	return ret;
}

inline static void __ipv4_free_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t *flow , unsigned short reason )
{
	unsigned char *buffer = 0;
	pntoh_ipv4_flow_t item = 0;
	pntoh_ipv4_flow_t fptr = 0;

	if ( !flow || !(*flow) )
		return;

	item = *flow;

	buffer = build_datagram ( session , item );

	/* notify to the user */
	( (pipv4_dfcallback_t) item->function )( item, &item->ident, buffer , item->meat , reason );
	free ( buffer );

	HASH_FIND(hh, session->flows, &item->ident, sizeof(item->ident), fptr);
	if (fptr) {
		HASH_DEL(session->flows, fptr);
	}
	// XXX: tcp put this somewhere else
	sem_post( &session->max_flows );

	free_lockaccess ( &item->lock );

	free( item );

	*flow = 0;

	return;
}

void ntoh_ipv4_free_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t *flow , unsigned short reason )
{
	if ( !params.init || !flow || !(*flow) )
		return;

	lock_access( &session->lock );

	lock_access ( &(*flow)->lock );
	__ipv4_free_flow ( session , flow , reason );

	unlock_access( &session->lock );

	return;
}

int ntoh_ipv4_add_fragment ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t flow , struct ip *iphdr )
{
	size_t			iphdr_len = 0;
	size_t			len = 0;
	unsigned short		offset = 0;
	unsigned short		flags = 0;
	unsigned int		data_len = 0;
	unsigned char		*data = 0;
	int			ret = NTOH_OK;
	pntoh_ipv4_fragment_t	frag = 0;

	if ( !params.init )
		return NTOH_NOT_INITIALIZED;

	if ( !session )
		return NTOH_INCORRECT_SESSION;

	if ( !flow )
		return NTOH_IP_INCORRECT_FLOW;

	if ( !iphdr )
		return NTOH_INCORRECT_IP_HEADER;

	/* check if it is an IPv4 packet */
	if ( iphdr->ip_v != 4 )
		return NTOH_NOT_IPV4;

	/* get IP header and data length */
	if ( ( iphdr_len = 4 * ( iphdr->ip_hl ) ) < sizeof(struct ip) )
		return NTOH_INCORRECT_IP_HEADER_LENGTH;

	if ( ( len = ntohs ( iphdr->ip_len ) ) <= iphdr_len )
		return NTOH_NOT_ENOUGH_DATA;

	data_len = len - iphdr_len;
	data = (unsigned char*) iphdr + iphdr_len;

	lock_access ( &flow->lock );

	/* check if addresses matches */
	if ( flow->ident.source != iphdr->ip_src.s_addr || flow->ident.destination != iphdr->ip_dst.s_addr )
	{
		ret = NTOH_IP_ADDRESSES_MISMATCH;
		goto exitp;
	}

	flags = ntohs( iphdr->ip_off );
	offset = NTOH_GET_IPV4_FRAGMENT_OFFSET(iphdr->ip_off);

	/* check if it is a fragment */
	if ( !( IS_SET(flags,IP_MF) || offset > 0 ) || IS_SET(flags,IP_DF) )
	{
		ret = NTOH_NOT_AN_IP_FRAGMENT;
		goto exitp;
	}

	/* checks if the fragment is hand crafted */
	if ( IS_SET(flags,IP_MF) && data_len < MIN_IPV4_FRAGMENT_LENGTH )
	{
		ret = NTOH_TOO_LOW_IP_FRAGMENT_LENGTH;
		goto exitp;
	}

	/* (1/2) checks if data length will overload max. amount of data allowed for an IPv4 datagram */
	if ( flow->meat + data_len > MAX_IPV4_DATAGRAM_LENGTH )
	{
		ret = NTOH_IP_FRAGMENT_OVERRUN;
		goto exitp;
	}

	/* (2/2) checks if data length will overload max. amount of data allowed for an IPv4 datagram */
	if ( offset + data_len > MAX_IPV4_DATAGRAM_LENGTH )
	{
		ret = NTOH_IP_FRAGMENT_OVERRUN;
		goto exitp;
	}

	sem_wait ( &session->max_fragments );

	/* inserts the new fragment into the list */
	frag = (pntoh_ipv4_fragment_t) calloc ( 1 , sizeof ( ntoh_ipv4_fragment_t ) );
	frag->len = data_len;
	frag->offset = offset;
	frag->data = (unsigned char*) calloc ( data_len , sizeof ( unsigned char ) );
	memcpy ( frag->data , data , data_len );
	flow->fragments = insert_fragment ( flow->fragments , frag );

	if ( flow->total < offset + data_len )
		flow->total = offset + data_len;

	flow->meat += data_len;

	/* it is the final fragment */
	if ( !IS_SET(flags,IP_MF) )
	{
		flow->final_iphdr = (struct ip*) calloc ( iphdr_len , sizeof ( unsigned char ) );
		memcpy ( flow->final_iphdr , iphdr , iphdr_len );
	}

	/* if there are no holes */
	if ( flow->final_iphdr != 0 && flow->total == flow->meat )
	{

		lock_access ( &session->lock );
		__ipv4_free_flow ( session , &flow , NTOH_REASON_DEFRAGMENTED_DATAGRAM );
		unlock_access ( &session->lock );
	}else
		gettimeofday( &flow->last_activ, 0 );

exitp:
	if ( flow != 0 )
		unlock_access ( &flow->lock );

	return ret;
}

unsigned int ntoh_ipv4_count_flows ( pntoh_ipv4_session_t session )
{
	unsigned int	ret = 0;
	unsigned int	count;

	if ( !params.init )
		return ret;

	lock_access( &params.lock );

	count = HASH_COUNT(session->flows);

	unlock_access( &params.lock );

	return ret;
}

inline static void ip_check_timeouts ( pntoh_ipv4_session_t session )
{
	struct timeval		tv = { 0 , 0 };
	pntoh_ipv4_flow_t	item;
	pntoh_ipv4_flow_t	tmp;
	unsigned int		i = 0;

	lock_access( &session->lock );

	gettimeofday ( &tv , 0 );

	/* iterates between flows */
	HASH_ITER(hh, session->flows, item, tmp)
	{
		/* timeout expired */
		if ( DEFAULT_IPV4_FRAGMENT_TIMEOUT < tv.tv_sec - item->last_activ.tv_sec )
		{
			lock_access ( &item->lock );
			__ipv4_free_flow ( session , &item , NTOH_REASON_TIMEDOUT_FRAGMENTS );
		}
	}

	unlock_access( &session->lock );

	return;
}

static void *timeouts_thread ( void *p )
{
	pthread_setcanceltype( PTHREAD_CANCEL_DEFERRED, 0 );

	while ( 1 )
	{
		ip_check_timeouts( (pntoh_ipv4_session_t) p );
		pthread_testcancel();
		sleep( 1 );
	}

	pthread_exit( 0 );
	//dummy return
	return 0;
}

pntoh_ipv4_session_t ntoh_ipv4_new_session ( unsigned int max_flows , unsigned long max_mem , unsigned int *error )
{
	pntoh_ipv4_session_t	session;
	unsigned int		max_fragments;

	if ( !max_flows )
		max_flows = DEFAULT_IPV4_MAX_FLOWS;

	if ( ! (session = (pntoh_ipv4_session_t) calloc ( 1 , sizeof ( ntoh_ipv4_session_t ) )) )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOMEM;
		return 0;
	}

	session->flows = NULL;
	sem_init ( &session->max_flows , 0 , max_flows );
	session->lock.use = 0;
	pthread_mutex_init ( &session->lock.mutex , 0 );
	pthread_cond_init ( &session->lock.pcond , 0 );

	max_fragments = (int)(max_mem / sizeof ( ntoh_ipv4_fragment_t ));
	if ( !max_fragments )
		max_fragments = DEFAULT_IPV4_MAX_FRAGMENTS;

	sem_init ( &session->max_fragments , 0 , max_fragments );

	ntoh_ipv4_init();

	lock_access ( &params.lock );

	if ( params.sessions_list != 0 )
		session->next = params.sessions_list;
	params.sessions_list = session;

	unlock_access ( &params.lock );

	if ( error != 0 )
		*error = NTOH_OK;

	pthread_create ( &session->tID , 0 , timeouts_thread , (void*) session );

	return session;
}

inline static void __ipv4_free_session ( pntoh_ipv4_session_t session )
{
	ntoh_ipv4_key_t		first = 0;
	pntoh_ipv4_session_t	ptr = 0;
	pntoh_ipv4_flow_t	item = 0;
	pntoh_ipv4_flow_t	tmp = 0;

	if ( !session )
		return;

	if ( params.sessions_list == session )
		params.sessions_list = session->next;
	else{
		for ( ptr = params.sessions_list ; ptr != 0 && ptr->next != session ; ptr = ptr->next );

		if ( ptr != 0 )
			ptr->next = session->next;
		else
			return;
	}

	lock_access( &session->lock );

	HASH_ITER(hh, session->flows, item, tmp) {
		lock_access ( &item->lock );
		__ipv4_free_flow ( session , &item , NTOH_REASON_EXIT );
	}

	HASH_CLEAR(hh, session->flows);

	pthread_cancel ( session->tID );
	pthread_join ( session->tID , 0 );
	sem_destroy ( &session->max_flows );
	sem_destroy ( &session->max_fragments );

	free_lockaccess ( &session->lock );

	free ( session );

	return;
}

void ntoh_ipv4_free_session ( pntoh_ipv4_session_t session )
{
	if ( !params.init || !session )
		return;

	lock_access ( &params.lock );

	__ipv4_free_session ( session );

	unlock_access ( &params.lock );

	return;
}

int ntoh_ipv4_resize_session ( pntoh_ipv4_session_t session , size_t newsize )
{
	if ( ! session )
		return NTOH_INCORRECT_SESSION;

	return NTOH_OK;
}

void ntoh_ipv4_init ( void )
{
	if ( params.init )
		return;

	params.lock.use = 0;
	pthread_mutex_init( &params.lock.mutex, 0 );
	pthread_cond_init( &params.lock.pcond, 0 );

	params.init = 1;
	return;
}

void ntoh_ipv4_exit ( void )
{
	if ( !params.init )
		return;

	lock_access ( &params.lock );

	while ( params.sessions_list != 0 )
		__ipv4_free_session ( params.sessions_list );

	unlock_access ( &params.lock );

	free_lockaccess ( &params.lock );

	params.init = 0;

	return;
}
