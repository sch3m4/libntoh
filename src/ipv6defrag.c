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


static ntoh_ipv6_params_t params = { 0 , 0 };

#define NTOH_GET_IPV6_FRAGMENT_OFFSET(offset)	(ntohs(offset)&~0x01)
#define NTOH_GET_IPV6_MORE_FRAGMENTS(offset)    ntohs(offset&IP6F_MORE_FRAG)
#define IS_SET(a,b)				(a & b)

/** @brief API to get the size of the flows table (max allowed flows) **/
unsigned int ntoh_ipv6_get_size ( pntoh_ipv6_session_t session )
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
unsigned int ntoh_ipv6_get_tuple4 ( struct ip6_hdr *ip , pntoh_ipv6_tuple4_t tuple )
{
	struct ip6_frag *frag;

	if ( !ip || !tuple )
		return NTOH_ERROR_PARAMS;

	/** @todo: only checks the first header, should we verify them all? **/
	if ( ip->ip6_nxt != IPPROTO_FRAGMENT )
		return NTOH_NOT_AN_IP_FRAGMENT;

	memcpy ( (void*)tuple->source , (void*)&(ip->ip6_src) , sizeof ( tuple->source) );
	memcpy ( (void*)tuple->destination , (void*)&(ip->ip6_dst) , sizeof ( tuple->destination) );

	frag = (struct ip6_frag*)((unsigned char*)ip + sizeof ( struct ip6_hdr));
	tuple->id = frag->ip6f_ident;  // we dont care byte order (no ntoX needed)
	tuple->protocol = frag->ip6f_nxt;

	return NTOH_OK;
}

unsigned short ipv6_equal_tuple ( void *a , void *b )
{
	unsigned short ret = 0;

        if ( ! memcmp ( a , (void*)&((pntoh_ipv6_flow_t)b)->ident , sizeof ( ntoh_ipv6_tuple4_t) ) )
		ret++;

	return ret;
}

pntoh_ipv6_flow_t ntoh_ipv6_find_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_tuple4_t tuple4 )
{
	ntoh_ipv6_key_t key = 0;
	pntoh_ipv6_flow_t ret = 0;

	if ( !params.init || !session || !tuple4 )
		return ret;

	key = ip_get_hashkey( tuple4 );

	lock_access( &session->lock );
	ret = htable_find ( session->flows , key, tuple4);

	unlock_access( &session->lock );

	return ret;
}

pntoh_ipv6_flow_t ntoh_ipv6_new_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_tuple4_t tuple4 , pipv6_dfcallback_t function , void *udata , unsigned int *error)
{
	pntoh_ipv6_flow_t ret = 0;

	if ( error != 0 )
        *error = 0;

	if ( !params.init )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_INIT;
		return ret;
	}

	if ( !session || !tuple4 || !function )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_PARAMS;
		return ret;
	}

	if ( sem_trywait( &session->max_flows ) != 0 )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOSPACE;

		return ret;
	}

	if ( !( ret = (pntoh_ipv6_flow_t) calloc( 1, sizeof(ntoh_ipv6_flow_t) ) ) )
		return ret;

	memcpy( &( ret->ident ), tuple4, sizeof(ntoh_ipv6_tuple4_t) );
	ret->key = ip_get_hashkey( tuple4 );

	gettimeofday( &ret->last_activ, 0 );
	ret->function = (void*) function;
	ret->udata = udata;

	ret->lock.use = 0;
	pthread_mutex_init ( &ret->lock.mutex , 0 );
	pthread_cond_init ( &ret->lock.pcond , 0 );

	lock_access( &session->lock );

	htable_insert ( session->flows , ret->key , ret );

	unlock_access( &session->lock );

	return ret;
}

/* insert a new fragment */
inline static pntoh_ipv6_fragment_t insert_fragment ( pntoh_ipv6_fragment_t list , pntoh_ipv6_fragment_t frag )
{
	pntoh_ipv6_fragment_t aux = list;

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

/* build the complete datagram from all collected IPv6 fragments */
inline static unsigned char *build_datagram ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t flow )
{
	pntoh_ipv6_fragment_t 	tmp;
	pntoh_ipv6_fragment_t 	fragment;
	struct ip6_hdr		*iphdr;
	unsigned int		offsethdr;
	unsigned char 		*ret;

	fragment = flow->fragments;
	iphdr = flow->final_iphdr;
	offsethdr = iphdr == 0 ? 0 : sizeof ( struct ip6_hdr );
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
		iphdr = (struct ip6_hdr*)ret;
		iphdr->ip6_plen = htons(flow->total);
		iphdr->ip6_nxt = flow->ident.protocol;
		free ( flow->final_iphdr );
		flow->meat += offsethdr;
		flow->total += offsethdr;
	}

	return ret;
}

inline static void __ipv6_free_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t *flow , unsigned short reason )
{
	unsigned char		*buffer = 0;
	pntoh_ipv6_flow_t	item = 0;

	if ( !flow || !(*flow) )
		return;

	item = *flow;

	buffer = build_datagram ( session , item );

	/* notify to the user */
	( (pipv6_dfcallback_t) item->function )( item, &item->ident, buffer , item->meat , reason );
	free ( buffer );

	htable_remove ( session->flows , item->key, &(item->ident) );

	sem_post( &session->max_flows );

	free_lockaccess ( &item->lock );

	free( item );

	*flow = 0;

	return;
}

void ntoh_ipv6_free_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t *flow , unsigned short reason )
{
	if ( !params.init || !flow || !(*flow) )
		return;

	lock_access( &session->lock );

	lock_access ( &(*flow)->lock );
	__ipv6_free_flow ( session , flow , reason );

	unlock_access( &session->lock );

	return;
}

int ntoh_ipv6_add_fragment ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t flow , struct ip6_hdr *iphdr )
{
	size_t                  iphdr_len = 0;
	unsigned short          offset = 0;
	unsigned int            data_len = 0;
	unsigned char           *data = 0;
	int			ret = NTOH_OK;
	pntoh_ipv6_fragment_t   frag = 0;
	struct ip6_frag         *frhdr = 0;
	size_t			len = 0;

	if ( !params.init )
		return NTOH_NOT_INITIALIZED;

	if ( !session )
		return NTOH_INCORRECT_SESSION;

	if ( !flow )
		return NTOH_IP_INCORRECT_FLOW;

	if ( !iphdr )
		return NTOH_INCORRECT_IP_HEADER;

	/* too short length */
	len = sizeof ( struct ip6_hdr ) + ntohs ( iphdr->ip6_plen );
	if ( len <= sizeof(struct ip6_hdr) + sizeof ( struct ip6_frag ) )
		return NTOH_INCORRECT_LENGTH;

	iphdr_len = sizeof ( struct ip6_hdr );

	data_len = ntohs( iphdr->ip6_plen ) - sizeof ( struct ip6_frag );
	data = (unsigned char*) iphdr + iphdr_len + sizeof ( struct ip6_frag );

	/* check if it is an IPv6 packet */
	if ( ((iphdr->ip6_vfc >> 4) & 0x0F) != 6 )
		return NTOH_NOT_IPV6;

	lock_access ( &flow->lock );

	/* check if addresses matches */
	if ( memcmp ( flow->ident.source , (const void*)&(iphdr->ip6_src) , sizeof ( flow->ident.source )) != 0 ||
		memcmp ( flow->ident.destination , (const void*)&(iphdr->ip6_dst) , sizeof ( flow->ident.destination )) != 0 )
	{
		ret = NTOH_IP_ADDRESSES_MISMATCH;
		goto exitp;
	}

	/** @todo: only checks the first header, should we verify them all? **/
	if ( iphdr->ip6_nxt != IPPROTO_FRAGMENT )
		return NTOH_NOT_AN_IP_FRAGMENT;

	frhdr = (struct ip6_frag*)((unsigned char*)iphdr + sizeof ( struct ip6_hdr));
	offset = NTOH_GET_IPV6_FRAGMENT_OFFSET(frhdr->ip6f_offlg);

	/* check if it is a fragment */
	if ( !( NTOH_GET_IPV6_MORE_FRAGMENTS(frhdr->ip6f_offlg) || offset > 0 ) )
	{
		ret = NTOH_NOT_AN_IP_FRAGMENT;
		goto exitp;
	}

	/* checks if the fragment is hand crafted */
	if ( NTOH_GET_IPV6_MORE_FRAGMENTS(frhdr->ip6f_offlg) && data_len < MIN_IPV6_FRAGMENT_LENGTH )
	{
		ret = NTOH_TOO_LOW_IP_FRAGMENT_LENGTH;
		goto exitp;
	}

	/* (1 / 2) checks if data length will overload max. amount of data allowed for an IPv6 datagram */
	if ( flow->meat + data_len > MAX_IPV6_DATAGRAM_LENGTH )
	{
		ret = NTOH_IP_FRAGMENT_OVERRUN;
		goto exitp;
	}

	/* (2 / 2) checks if data length will overload max. amount of data allowed for an IPv6 datagram */
	if ( offset + data_len > MAX_IPV6_DATAGRAM_LENGTH )
	{
		ret = NTOH_IP_FRAGMENT_OVERRUN;
		goto exitp;
	}

	sem_wait ( &session->max_fragments );

	/* inserts the new fragment into the list */
	frag = (pntoh_ipv6_fragment_t) calloc ( 1 , sizeof ( ntoh_ipv6_fragment_t ) );
	frag->len = data_len;
	frag->offset = offset;
	frag->data = (unsigned char*) calloc ( data_len , sizeof ( unsigned char ) );
	memcpy ( frag->data , data , data_len );
	flow->fragments = insert_fragment ( flow->fragments , frag );

	if ( flow->total < offset + data_len )
		flow->total = offset + data_len;

	flow->meat += data_len;

	/* it is the final fragment? */
	if ( ! NTOH_GET_IPV6_MORE_FRAGMENTS(frhdr->ip6f_offlg) )
	{
		flow->final_iphdr = (struct ip6_hdr*) calloc ( iphdr_len , sizeof ( unsigned char ) );
		memcpy ( flow->final_iphdr , iphdr , iphdr_len );
	}

	/* if there are no holes */
	if ( flow->final_iphdr != 0 && flow->total == flow->meat )
	{
		lock_access ( &session->lock );
		__ipv6_free_flow ( session , &flow , NTOH_REASON_DEFRAGMENTED_DATAGRAM );
		unlock_access ( &session->lock );
	}else
		gettimeofday( &flow->last_activ, 0 );

exitp:
	if ( flow != 0 )
		unlock_access ( &flow->lock );

	return ret;
}

unsigned int ntoh_ipv6_count_flows ( pntoh_ipv6_session_t session )
{
	unsigned int	ret = 0;
	int		count;

	if ( !params.init )
		return ret;

	lock_access( &params.lock );

        sem_getvalue ( &session->max_flows , &count );
        ret = session->flows->table_size - count;
//	ret = htable_count ( session->flows );

	unlock_access( &params.lock );

	return ret;
}

inline static void ip_check_timeouts ( pntoh_ipv6_session_t session )
{
	struct timeval		tv = { 0 , 0 };
	pntoh_ipv6_flow_t	item;
	unsigned int		i = 0;
	phtnode_t		node = 0;
	phtnode_t		prev = 0;

	lock_access( &session->lock );

	/* handly iterates between flows */
	for ( i = 0 ; i < session->flows->table_size ; i++ )
	{
		gettimeofday ( &tv , 0 );
		node = prev = session->flows->table[i];
		while ( node != 0 )
		{
			item = (pntoh_ipv6_flow_t) node->val;

			/* timeout expired */
			if ( DEFAULT_IPV6_FRAGMENT_TIMEOUT < tv.tv_sec - item->last_activ.tv_sec )
			{
				lock_access ( &item->lock );
				__ipv6_free_flow ( session , &item , NTOH_REASON_TIMEDOUT_FRAGMENTS );
				if (node != prev)
				      node = prev;
				else
				      node = 0;
			}else{
				prev = node;
				node = node->next;
			}
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
		ip_check_timeouts( (pntoh_ipv6_session_t) p );
		pthread_testcancel();
		sleep( 1 );
	}

	pthread_exit( 0 );
	//dummy return
	return 0;
}

pntoh_ipv6_session_t ntoh_ipv6_new_session ( unsigned int max_flows , unsigned long max_mem , unsigned int *error )
{
	pntoh_ipv6_session_t	session;
	unsigned int		max_fragments;

	if ( !max_flows )
		max_flows = DEFAULT_IPV6_MAX_FLOWS;

	if ( ! (session = (pntoh_ipv6_session_t) calloc ( 1 , sizeof ( ntoh_ipv6_session_t ) )) )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOMEM;
		return 0;
	}

	session->flows = htable_map (max_flows , &ipv6_equal_tuple );
	sem_init ( &session->max_flows , 0 , max_flows );
	session->lock.use = 0;
	pthread_mutex_init ( &session->lock.mutex , 0 );
	pthread_cond_init ( &session->lock.pcond , 0 );

	max_fragments = (int)(max_mem / sizeof ( ntoh_ipv6_fragment_t ));
	if ( !max_fragments )
		max_fragments = DEFAULT_IPV6_MAX_FRAGMENTS;

	sem_init ( &session->max_fragments , 0 , max_fragments );

	ntoh_ipv6_init();

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

inline static void __ipv6_free_session ( pntoh_ipv6_session_t session )
{
	ntoh_ipv6_key_t	first = 0;
	pntoh_ipv6_session_t ptr = 0;
	pntoh_ipv6_flow_t item = 0;

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

	while ( ( first = htable_first ( session->flows ) ) != 0 )
	{
		lock_access ( &item->lock );
		__ipv6_free_flow ( session , &item , NTOH_REASON_EXIT );
	}

	htable_destroy ( &(session->flows) );

	pthread_cancel ( session->tID );
	pthread_join ( session->tID , 0 );
	sem_destroy ( &session->max_flows );
	sem_destroy ( &session->max_fragments );

	free_lockaccess ( &session->lock );

    free ( session );

    return;
}

void ntoh_ipv6_free_session ( pntoh_ipv6_session_t session )
{
	if ( !params.init || !session )
		return;

	lock_access ( &params.lock );

	__ipv6_free_session ( session );

	unlock_access ( &params.lock );

    return;
}

int ntoh_ipv6_resize_session ( pntoh_ipv6_session_t session , size_t newsize )
{
        pipv6_flows_table_t	newht = 0 , curht = 0;
        pntoh_ipv6_flow_t	item = 0;
        int                     current = 0;

	if ( ! session )
		return NTOH_INCORRECT_SESSION;

	if ( ! newsize || newsize == session->flows->table_size )
		return NTOH_OK;

	lock_access ( &session->lock );

	curht = session->flows;

        // increase the size
        if ( newsize > curht->table_size )
                newht = htable_map ( newsize , &ipv6_equal_tuple );
        // decrease the size
        else
        {
                sem_getvalue ( &session->max_flows , &current );
                if ( newsize < current )
                {
                        unlock_access ( &session->lock );
                        return NTOH_ERROR_NOSPACE;
                }
        }

        // moves all the flows to the new sessions table
        while ( ( current = htable_first ( curht ) ) != 0 )
        {
                item = (pntoh_ipv6_flow_t) htable_remove ( curht , current , 0 );
                htable_insert ( newht , current , item );
        }
        htable_destroy ( &curht );

	sem_init ( &session->max_flows , 0 , newsize );
	session->flows = newht;

	unlock_access ( &session->lock );

	return NTOH_OK;
}


void ntoh_ipv6_init ( void )
{
	if ( params.init )
		return;

	params.lock.use = 0;
	pthread_mutex_init( &params.lock.mutex, 0 );
	pthread_cond_init( &params.lock.pcond, 0 );

	params.init = 1;
	return;
}

void ntoh_ipv6_exit ( void )
{
	if ( !params.init )
		return;

	lock_access ( &params.lock );

	while ( params.sessions_list != 0 )
		__ipv6_free_session ( params.sessions_list );

	unlock_access ( &params.lock );

	free_lockaccess ( &params.lock );

	params.init = 0;

	return;
}
