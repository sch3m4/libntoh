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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <libntoh.h>

static ntoh_tcp_params_t params = { 0 , 0 };

#define IS_TIMEWAIT(peer,side) (peer.status == DEFAULT_TCP_TIMEWAIT_TIMEOUT || side.status == DEFAULT_TCP_TIMEWAIT_TIMEOUT )

static const char tcp_status[][1024] = {
		"Closed",
		"Listen",
		"SYN Sent",
		"SYN Rcv",
		"Established",
		"Closing",
		"Close Wait",
		"Fin Wait1",
		"Fin Wait2",
		"Last ACK",
		"Time Wait"
};

/** @brief API to get the string description associated to the given value corresponding with a TCP status **/
const char *ntoh_tcp_get_status ( unsigned int status )
{
	if ( status > NTOH_STATUS_TIMEWAIT )
		return 0;

	return tcp_status[status];
}

/** @brief Returns the key for the stream identified by 'data' **/
inline static ntoh_tcp_key_t tcp_getkey ( pntoh_tcp_session_t session , pntoh_tcp_tuple5_t data )
{
	#define ARRAY_SIZE	(IP6_ADDR_LEN*2)+2
	unsigned int	val[ARRAY_SIZE] = {0};
	size_t		len = ARRAY_SIZE;

	if ( !data || !session )
		return 0;

	if ( data->protocol != IPPROTO_IPV6 )
		len -= (IP6_ADDR_LEN - IP4_ADDR_LEN) * 2;

	memcpy ( (void*) val , (void*)data->source , len );
	val[len] = data->protocol;
	memcpy ( (void*) &val[len] , (void*)data->destination , IP6_ADDR_LEN );
	val[(len*2)+1] = data->sport | (data->dport << 16);

	return sfhash ( val , len , session->rand );
/*
	return (
			( ( ( data->sport | (data->protocol & 0x0F) ) & 0xFF ) |
			( ( ( data->dport | (data->protocol & 0xF0) ) & 0xFF ) << 8 ) |
			( ( data->source & 0xFF ) << 16 ) |
			( ( data->destination & 0xFF ) << 24 ) )
		);*/
}

/** @brief Sends the given segment to the user **/
inline static void send_single_segment ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , pntoh_tcp_peer_t origin , pntoh_tcp_peer_t destination , pntoh_tcp_segment_t segment , int reason , int extra )
{
	//send this segment
	if ( extra != NTOH_REASON_OOO )
		origin->next_seq = segment->seq + segment->payload_len;

	origin->totalwin += segment->payload_len;

	if ( segment->flags & ( TH_FIN | TH_RST ) )
	{
		origin->status = NTOH_STATUS_FINWAIT1;
		destination->status = NTOH_STATUS_CLOSEWAIT;
		stream->status = NTOH_STATUS_CLOSING;

		if ( origin == &stream->client )
			stream->closedby = NTOH_CLOSEDBY_CLIENT;
		else if ( origin == &stream->server )
			stream->closedby = NTOH_CLOSEDBY_SERVER;

		if ( origin->final_seq == 0 )
			origin->final_seq = segment->seq;

		origin->next_seq++;
	}

	if ( origin->receive )
		((pntoh_tcp_callback_t) stream->function) ( stream , origin , destination , segment , reason , extra );

	free ( segment );

	return;
}

/** @brief Sends all segment stored in a peer queue **/
inline static void flush_peer_queues ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , unsigned short extra )
{
	pntoh_tcp_peer_t	peers[2] = { &stream->client , &stream->server };
	pntoh_tcp_segment_t	seg = 0;
	unsigned int		i = 0;

	for ( i = 0 ; i < 2 ; i++ )
		while ( peers[i]->segments != 0 )
		{
			seg = peers[i]->segments;
			if (i == 0)
				seg->origin = NTOH_SENT_BY_CLIENT;
			else
				seg->origin = NTOH_SENT_BY_SERVER;

			peers[i]->segments = seg->next;

			send_single_segment(session,stream,peers[i],peers[(i+1)%2] , seg , seg->payload_len > 0 ? NTOH_REASON_DATA : NTOH_REASON_SYNC , extra );
		}
}

/** @brief Remove the stream from the session streams hash table, and notify the user **/
inline static void delete_stream ( pntoh_tcp_session_t session , pntoh_tcp_stream_t *stream , int reason , int extra )
{
	pntoh_tcp_stream_t item = 0;
	pntoh_tcp_stream_t sptr;

	if ( !stream || !(*stream) )
		return;

	item = *stream;

	if ( session->streams != 0)
	{
		HASH_FIND(hh, session->streams, &item->tuple, sizeof(item->tuple), sptr);
		if (sptr) {
			HASH_DEL(session->streams, sptr);
			sem_post ( &session->max_streams );
		}
	}

	if ( session->timewait != 0)
	{
		HASH_FIND(hh, session->timewait, &item->tuple, sizeof(item->tuple), sptr);
		if (sptr) {
			HASH_DEL(session->timewait, sptr);
			sem_post ( &session->max_timewait );
		}
	}

	switch ( extra )
	{
		case NTOH_MAX_SYN_RETRIES_REACHED:
			extra = NTOH_REASON_MAX_SYN_RETRIES_REACHED;
			break;

		case NTOH_MAX_SYNACK_RETRIES_REACHED:
			extra = NTOH_REASON_MAX_SYNACK_RETRIES_REACHED;
			break;

		case NTOH_HANDSHAKE_FAILED:
			extra = NTOH_REASON_HSFAILED;
			break;
	}

	if ( item->client.receive )
		((pntoh_tcp_callback_t)item->function)(item,&item->client, &item->server,0, reason , extra );

	free_lockaccess ( &item->lock );

	free ( item );
	*stream = 0;

	return;
}

/** @brief Frees a TCP stream **/
inline static void __tcp_free_stream ( pntoh_tcp_session_t session , pntoh_tcp_stream_t *stream , int reason , int extra )
{
	flush_peer_queues ( session , *stream , extra );
	delete_stream ( session , stream , reason , extra );

	return;
}

/** @brief Frees a TCP session **/
inline static void __tcp_free_session ( pntoh_tcp_session_t session )
{
	pntoh_tcp_session_t	ptr = 0;
	pntoh_tcp_stream_t 	item = 0;
	pntoh_tcp_stream_t 	tmp = 0;
	ntoh_tcp_key_t		first = 0;

	if ( params.sessions_list == session )
		params.sessions_list = session->next;
	else{
		for ( ptr = params.sessions_list ; ptr != 0 && ptr->next != session ; ptr = ptr->next );
		if ( ptr != 0 )
			ptr->next = session->next;
	}

	lock_access( &session->lock );

	HASH_ITER(hh, session->timewait, item, tmp) {
		HASH_DEL(session->timewait, item);
		lock_access ( &item->lock );
		__tcp_free_stream ( session , &item , NTOH_REASON_SYNC , NTOH_REASON_EXIT );
	}

	HASH_ITER(hh, session->streams, item, tmp) {
		HASH_DEL(session->streams, item);
		lock_access ( &item->lock );
		__tcp_free_stream ( session , &item , NTOH_REASON_SYNC , NTOH_REASON_EXIT );
	}

	HASH_CLEAR(hh, session->streams);
	HASH_CLEAR(hh, session->timewait);

	unlock_access( &session->lock );

	pthread_cancel ( session->tID );
	pthread_join ( session->tID , 0 );
	sem_destroy ( &session->max_streams );
	sem_destroy ( &session->max_timewait );

	free_lockaccess ( &session->lock );

	free ( session );

	return;
}

inline static void tcp_check_timeouts ( pntoh_tcp_session_t session )
{
	#define IS_FINWAIT2(peer,side) (peer.status == NTOH_STATUS_FINWAIT2 || side.status == NTOH_STATUS_FINWAIT2 )

	struct timeval		tv = { 0 , 0 };
	unsigned int		val = 0;
	unsigned int		i = 0;
	unsigned short		timedout = 0;
	pntoh_tcp_stream_t	item;
	pntoh_tcp_stream_t	tmp;

	lock_access( &session->lock );

	gettimeofday ( &tv , 0 );

	/* iterating manually between flows */
	HASH_ITER(hh, session->streams, item, tmp) {
		timedout = 0;
		val = tv.tv_sec - item->last_activ.tv_sec;

		switch ( item->status )
		{
			case NTOH_STATUS_SYNSENT:
				if ( (item->enable_check_timeout & NTOH_CHECK_TCP_SYNSENT_TIMEOUT) && (val > DEFAULT_TCP_SYNSENT_TIMEOUT) )// @contrib: di3online - https://github.com/di3online
					timedout = 1;
				break;

			case NTOH_STATUS_SYNRCV:
				if ( (item->enable_check_timeout & NTOH_CHECK_TCP_SYNRCV_TIMEOUT) && (val > DEFAULT_TCP_SYNRCV_TIMEOUT) )// @contrib: di3online - https://github.com/di3online
					timedout = 1;
				break;

			case NTOH_STATUS_ESTABLISHED:
				if ( (item->enable_check_timeout & NTOH_CHECK_TCP_ESTABLISHED_TIMEOUT) && (val > DEFAULT_TCP_ESTABLISHED_TIMEOUT) )// @contrib: di3online - https://github.com/di3online
					timedout = 1;
				break;

			case NTOH_STATUS_CLOSING:
				if ( IS_FINWAIT2(item->client,item->server) && (item->enable_check_timeout & NTOH_CHECK_TCP_FINWAIT2_TIMEOUT) && (val < DEFAULT_TCP_FINWAIT2_TIMEOUT) )// @contrib: di3online - https://github.com/di3online
					timedout = 1;
				else if ( IS_TIMEWAIT(item->client,item->server) && (item->enable_check_timeout & NTOH_CHECK_TCP_TIMEWAIT_TIMEOUT) &&  val < DEFAULT_TCP_TIMEWAIT_TIMEOUT )// @contrib: di3online - https://github.com/di3online
					timedout = 1;
				break;
		}

		/* timeout expired */
		if ( timedout )
		{
			lock_access ( &item->lock );
			__tcp_free_stream ( session , &item , NTOH_REASON_SYNC , NTOH_REASON_TIMEDOUT );
			HASH_DEL(session->streams, item);
		}
	}

	/* handly iterates between flows */
	HASH_ITER(hh, session->timewait, item, tmp) {
		val = tv.tv_sec - item->last_activ.tv_sec;

		if ( (item->enable_check_timeout & NTOH_CHECK_TCP_TIMEWAIT_TIMEOUT) && val > DEFAULT_TCP_TIMEWAIT_TIMEOUT )// @contrib: di3online - https://github.com/di3online
		{
			lock_access ( &item->lock );
			__tcp_free_stream ( session , &item , NTOH_REASON_SYNC , NTOH_REASON_TIMEDOUT );
			HASH_DEL(session->timewait, item);
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
		tcp_check_timeouts( (pntoh_tcp_session_t) p );
		pthread_testcancel();
		poll ( 0 , 0 , DEFAULT_TIMEOUT_DELAY );
	}

	pthread_exit( 0 );
	//dummy return
	return 0;
}

/** @brief API to get a tuple5 **/
unsigned int ntoh_tcp_get_tuple5 ( void *ip , struct tcphdr *tcp , pntoh_tcp_tuple5_t tuple )
{
	struct ip6_hdr	*ip6hdr = (struct ip6_hdr*)ip;
	struct ip	*ip4hdr = (struct ip*)ip;

	if ( !ip || !tcp || !tuple )
		return NTOH_ERROR_PARAMS;

	switch ( ip4hdr->ip_v )
	{
		case 4:
			memset ( (void*)tuple->source , 0 , sizeof(tuple->source) );
			memset ( (void*)tuple->destination , 0 , sizeof ( tuple->destination ) );
			/* pointer already set */
			// ip4hdr = (struct ip*)ip;
			tuple->protocol = 4;
			tuple->source[0] = ip4hdr->ip_src.s_addr;
			tuple->destination[0] = ip4hdr->ip_dst.s_addr;
			break;

		case 6:
			tuple->protocol = 6;
			memcpy ( (void*)tuple->source , (void*)&(ip6hdr->ip6_src) , sizeof ( tuple->source) );
			memcpy ( (void*)tuple->destination , (void*)&(ip6hdr->ip6_dst) , sizeof ( tuple->destination) );
			break;

		default:
                	return NTOH_INCORRECT_IP_HEADER;
	}

	tuple->sport = tcp->th_sport;
	tuple->dport = tcp->th_dport;

	return NTOH_OK;
}

/** @brief API to get the size of the sessions table (max allowed streams) **/
unsigned int ntoh_tcp_get_size ( pntoh_tcp_session_t session )
{
	unsigned int ret = 0;

	if ( !session )
		return ret;

	lock_access ( & (session->lock) );
	ret = -1;
	unlock_access ( & (session->lock) );

	return ret;
}

/** @brief API to create a new session and add it to the global sessions list **/
pntoh_tcp_session_t ntoh_tcp_new_session ( unsigned int max_streams , unsigned int max_timewait , unsigned int *error )
{
	pntoh_tcp_session_t session;

	if ( !max_streams )
		max_streams = DEFAULT_TCP_MAX_STREAMS;

	if ( !max_timewait )
		max_timewait = DEFAULT_TCP_MAX_TIMEWAIT_STREAMS(max_streams);

	if ( ! (session = (pntoh_tcp_session_t) calloc ( 1 , sizeof ( ntoh_tcp_session_t ) ) ) )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOMEM;
		return 0;
	}

	ntoh_tcp_init();

	session->streams = NULL;
	session->timewait = NULL;

	sem_init ( &session->max_streams , 0 , max_streams );
	sem_init ( &session->max_timewait , 0 , max_timewait );

	session->lock.use = 0;
	pthread_mutex_init( &session->lock.mutex, 0 );
	pthread_cond_init( &session->lock.pcond, 0 );

	srand((int)time(NULL));

	session->rand = rand();


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

/** @brief API to free a TCP session (wrapper) **/
void ntoh_tcp_free_session ( pntoh_tcp_session_t session )
{
	if ( !session )
		return;

	lock_access ( &params.lock );

	__tcp_free_session ( session );

	unlock_access ( &params.lock );


	return;
}

/** @brief API to free a TCP stream (wrapper) **/
void ntoh_tcp_free_stream ( pntoh_tcp_session_t session , pntoh_tcp_stream_t *stream , int reason , int extra )
{
	if ( !session || !stream || !(*stream) )
		return;

	lock_access( &session->lock );

	lock_access( &(*stream)->lock );
	__tcp_free_stream ( session , stream , reason ,extra );

	unlock_access(&session->lock);

	return;
}

/** @brief API to release all used TCP resources (sessions and streams) **/
void ntoh_tcp_exit( void )
{
	if ( !params.init )
		return;

	lock_access ( &params.lock );

	while ( params.sessions_list != 0 )
		__tcp_free_session ( params.sessions_list );

	unlock_access ( &params.lock );

	free_lockaccess ( &params.lock );

	params.init = 0;

	return;
}

/** @brief API to initialize the global structure **/
void ntoh_tcp_init ( void )
{
	if ( params.init )
		return;

	params.lock.use = 0;
	pthread_mutex_init( &params.lock.mutex, 0 );
	pthread_cond_init( &params.lock.pcond, 0 );

	params.init = 1;

	return;
}

/** @brief API to look for a TCP stream identified by 'tuple5' **/
pntoh_tcp_stream_t ntoh_tcp_find_stream ( pntoh_tcp_session_t session , pntoh_tcp_tuple5_t tuple5 )
{
	ntoh_tcp_key_t		key = 0;
	ntoh_tcp_tuple5_t	tuplerev = {{0},{0},0};
	pntoh_tcp_stream_t	ret = 0;
	unsigned int		i;

	if ( !session || !tuple5 )
		return ret;

	key = tcp_getkey( session , tuple5 );

	lock_access( &session->lock );

	HASH_FIND(hh, session->streams, tuple5, sizeof(*tuple5), ret);
	if ( ! ret )
	{
		for ( i = 0 ; i < IP6_ADDR_LEN ; i++ )
		{
			tuplerev.destination[i] = tuple5->source[i];
			tuplerev.source[i] = tuple5->destination[i];
		}

		tuplerev.sport = tuple5->dport;
		tuplerev.dport = tuple5->sport;
		tuplerev.protocol = tuple5->protocol;

		key = tcp_getkey( session , &tuplerev );

		HASH_FIND(hh, session->streams, &tuplerev, sizeof(tuplerev), ret);
	}

	unlock_access( &session->lock );

	return ret;
}

/** @brief API to create a new TCP stream and add it to the given session **/
pntoh_tcp_stream_t ntoh_tcp_new_stream ( pntoh_tcp_session_t session , pntoh_tcp_tuple5_t tuple5 , pntoh_tcp_callback_t function ,void *udata , unsigned int *error, unsigned short enable_check_timeout, unsigned short enable_check_nowindow )
{
	pntoh_tcp_stream_t	stream = 0;
	ntoh_tcp_key_t		key = 0;
	unsigned int		i;

	if ( error != 0 )
		*error = 0;

	if ( !session )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_PARAMS;
		return 0;
	}

	if ( !(key = tcp_getkey( session , tuple5 )) )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOKEY;
		return 0;
	}

	if ( !function )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_NOFUNCTION;
		return 0;
	}

	if ( !tuple5->dport || !tuple5->sport || !tuple5->protocol )
	{
		if ( error != 0 )
			*error = NTOH_ERROR_INVALID_TUPLE5;
		return 0;
	}

	lock_access( &session->lock );

	if ( sem_trywait( &session->max_streams ) != 0 )
	{
		unlock_access( &session->lock );
		if ( error != 0 )
			*error = NTOH_ERROR_NOSPACE;
		return 0;
	}

	if ( !( stream = (pntoh_tcp_stream_t) calloc( 1, sizeof ( ntoh_tcp_stream_t ) ) ) )
	{
		unlock_access( &session->lock );

		if ( error != 0 )
			*error = NTOH_ERROR_NOMEM;
		return 0;
	}

	memcpy( (void*)&( stream->tuple ), (void*)tuple5, sizeof(ntoh_tcp_tuple5_t) );

	for ( i = 0 ; i < IP6_ADDR_LEN ; i++ )
	{
		stream->client.addr[i] = stream->tuple.source[i];
		stream->server.addr[i] = stream->tuple.destination[i];
	}

	stream->client.port = stream->tuple.sport;
	stream->server.port = stream->tuple.dport;
	stream->client.receive = 1;
	stream->server.receive = 1;

	gettimeofday( &stream->last_activ, 0 );
	stream->status = stream->client.status = stream->server.status = NTOH_STATUS_CLOSED;
	stream->function = (void*) function;
	stream->udata = udata;
	stream->enable_check_timeout = enable_check_timeout;// @contrib: di3online - https://github.com/di3online
	stream->enable_check_nowindow = enable_check_nowindow;// @contrib: di3online - https://github.com/di3online

	stream->lock.use = 0;
	pthread_mutex_init( &stream->lock.mutex, 0 );
	pthread_cond_init( &stream->lock.pcond, 0 );

	HASH_ADD(hh, session->streams, tuple, sizeof(ntoh_tcp_tuple5_t), stream);

	unlock_access( &session->lock );

	if ( error != 0 )
		*error = NTOH_OK;

	return stream;
}

/** @brief API to get the amount of streams stored in a session **/
unsigned int ntoh_tcp_count_streams ( pntoh_tcp_session_t session )
{
	unsigned int	ret = 0;
	unsigned int	count;

	if ( !session )
		return ret;

	lock_access( &session->lock );

	count = HASH_COUNT(session->streams);

	unlock_access( &session->lock );
	return ret;
}

/** @brief Gets the TCP options from a TCP header **/
inline static void get_tcp_options ( pntoh_tcp_peer_t peer , struct tcphdr *tcp , size_t tcp_len )
{
        unsigned char *options = 0;
        unsigned int aux = 0;

        if ( tcp_len == sizeof(struct tcphdr) )
                return;

        options = (unsigned char*) tcp + sizeof(struct tcphdr);
        peer->wsize = (unsigned int) ntohs( tcp->th_win );
        peer->wscale = 0;

        while ( options < (unsigned char*) tcp + tcp_len )
        {
                switch ( *options )
                {
                        case TCPOPT_MAXSEG:
                                memcpy( &aux, ( options + 2 ), TCPOLEN_MAXSEG - 2 );
                                peer->mss = (unsigned short) ntohs( aux );
                                options += TCPOLEN_MAXSEG;
                                break;

                        case TCPOPT_SACK_PERMITTED:
                                if ( *( options + 1 ) == TCPI_OPT_SACK )
                                        peer->sack = 1;

                                options += TCPOLEN_SACK_PERMITTED;
                                break;

                        case TCPOPT_TIMESTAMP:
                                options += TCPOLEN_TIMESTAMP;
                                break;

                        case TCPOPT_WINDOW:
                                memcpy( &aux, ( options + 2 ), TCPOLEN_WINDOW - 2 );
                                peer->wscale = (unsigned int) aux;
                                options += TCPOLEN_WINDOW;
                                break;

                        case TCPOPT_EOL:
                                /* exit */
                                options = (unsigned char*) tcp + tcp_len;
                                break;

                        case TCPOPT_NOP:
                        default:
                                options++;
                                break;
                }
        }

        return;
}

/** @brief Gets the TCP Timestamp from TCP Options header **/
inline static void get_timestamp ( struct tcphdr *tcp , size_t tcp_len , unsigned int *ts )
{
    unsigned char *options = 0;
    unsigned int tmp = 0;

    if ( tcp_len == sizeof(struct tcphdr) )
            return;

    options = (unsigned char*) tcp + sizeof(struct tcphdr);
    while ( options < (unsigned char*) tcp + tcp_len )
    {
            switch ( *options )
            {
                    case TCPOPT_MAXSEG:
                            options += TCPOLEN_MAXSEG;
                            break;

                    case TCPOPT_SACK_PERMITTED:
                            options += TCPOLEN_SACK_PERMITTED;
                            break;

                    case TCPOPT_TIMESTAMP:
                    		memcpy ( (unsigned char*) &tmp , options + 2 , 4 );// get TSval
                    		*ts = ntohl(tmp);
                            options += TCPOLEN_TIMESTAMP;
                            break;

                    case TCPOPT_WINDOW:
                            options += TCPOLEN_WINDOW;
                            break;

                    case TCPOPT_EOL:
                            /* exit */
                            options = (unsigned char*) tcp + tcp_len;
                            break;

                    case TCPOPT_NOP:
                    default:
                            options++;
                            break;
            }
    }
}

/** @brief Adds a segment to the given peer queue **/
inline static void queue_segment ( pntoh_tcp_session_t session , pntoh_tcp_peer_t peer , pntoh_tcp_segment_t segment )
{
	pntoh_tcp_segment_t	qu = 0;

	if ( !peer )
		return;

	if ( peer->segments == 0 )
		peer->segments = segment;
	else{
		if ( segment->seq < peer->segments->seq )
		{
			segment->next = peer->segments;
			peer->segments = segment;
		}else{
			// insert the new segment into the list
			for ( qu = peer->segments ; qu->next != 0 && qu->next->seq < segment->seq ; qu = qu->next );

			segment->next = qu->next;
			qu->next = segment;
		}
	}

	peer->totalwin -= segment->payload_len;

	return;
}

/** @brief Creates a new segment **/
inline static pntoh_tcp_segment_t new_segment ( unsigned long seq , unsigned long ack , unsigned long payload_len , unsigned char flags , void *udata )
{
	pntoh_tcp_segment_t ret = 0;

	// allocates the new segment
	ret = (pntoh_tcp_segment_t) calloc ( 1 , sizeof ( ntoh_tcp_segment_t ) );
	ret->ack = ack;
	ret->seq = seq;
	ret->payload_len = payload_len;
	ret->flags = flags;
	ret->user_data = udata;
	gettimeofday ( &ret->tv , 0 );

	return ret;
}

/** @brief Sends all possible segments to the user or only the first one **/
inline static unsigned int send_peer_segments ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , pntoh_tcp_peer_t origin , pntoh_tcp_peer_t destination , unsigned int ack , unsigned short first , int extra, int who )
{
	pntoh_tcp_segment_t 	segment = 0;
	unsigned int		ret = 0;


	if ( !origin->segments )
		return ret;

	/* forces to send the first segment */
	if ( first )
	{
		if ( (segment = origin->segments) == 0 )
			return ret;

		/*if ( ! segment->payload_len )
			return ret;*/

	        segment->origin = who;// @contrib: di3online - https://github.com/di3online

	        origin->segments = segment->next;

		send_single_segment ( session , stream , origin , destination , segment , segment->payload_len > 0 ? NTOH_REASON_DATA : NTOH_REASON_SYNC , extra );
		ret++;

		return ret;
	}

	while ( origin->segments != 0 && origin->next_seq <= ack )
	{
		if ( origin->segments->seq == origin->next_seq )
			goto tosend;
		else if ( origin->segments->seq < origin->next_seq )
		{
			extra = NTOH_REASON_OOO;
			goto tosend;
		}else { // @contrib: di3online - https://github.com/di3online
			extra = NTOH_REASON_SEGMENT_LOST; /// NTOH_REASON_XXX; @contrib: sch3m4 - lost segment
			// break; // before treatment is not followed by processing problems in testing POST uploaded file (incomplete)
			          // Add a new option to continue treatment now, but this option is how to deal with the follow-up
			          // For example, a reference window OOO did not do

			//goto tosend;
			break; /* do not send segment if a previos one is lost */
        	}

		tosend:
			/* unlink the segment */
			segment = origin->segments;
			segment->origin = who;// @contrib: di3online - https://github.com/di3online

			origin->segments = segment->next;

			send_single_segment ( session , stream , origin , destination , segment , segment->payload_len > 0 ? NTOH_REASON_DATA : NTOH_REASON_SYNC, extra );
			ret++;
	}

	return ret;
}

/** @brief Handles the connection establishment **/
inline static int handle_new_connection ( pntoh_tcp_stream_t stream , struct tcphdr *tcp , pntoh_tcp_peer_t origin , pntoh_tcp_peer_t destination , void *udata )
{
	unsigned long seq = ntohl(tcp->th_seq);
	unsigned long ack = ntohl(tcp->th_ack);

	/* switch between possibles connection status */
	switch ( stream->status )
	{
		// Client --- SYN ---> Server
		case NTOH_STATUS_CLOSED:

			if ( tcp->th_flags != TH_SYN )
			{
				if ( DEFAULT_TCP_SYN_RETRIES < stream->syn_retries++ )
					return NTOH_MAX_SYN_RETRIES_REACHED;

				return NTOH_OK;
			}

			/* as we have a SYN flag, get tcp options */
			get_tcp_options ( origin , tcp , tcp->th_off * 4 );
			origin->totalwin = origin->wsize << origin->wscale;

			/* store seq number as ISN */
			origin->isn = seq;
			origin->next_seq = ( seq - origin->isn ) + 1;
			destination->ian = origin->isn;

			origin->status = NTOH_STATUS_SYNSENT;
			destination->status = NTOH_STATUS_LISTEN;
			stream->status = NTOH_STATUS_SYNSENT;

			break;

		// Server --- SYN + ACK ---> Client
		case NTOH_STATUS_SYNSENT:
			if ( tcp->th_flags != (TH_SYN | TH_ACK) || ( ( ack - origin->ian ) != destination->next_seq ))
			{
				if ( DEFAULT_TCP_SYNACK_RETRIES < stream->synack_retries++ )
					return NTOH_MAX_SYNACK_RETRIES_REACHED;

				return NTOH_OK;
			}

			/* as we have a SYN flag, get tcp options */
			get_tcp_options ( origin , tcp , tcp->th_off * 4 );
			origin->totalwin = origin->wsize << origin->wscale;

			/* store ack number as IAN */
			origin->isn = seq;
			origin->next_seq = ( seq - origin->isn ) + 1;
			destination->ian = origin->isn;

			origin->status = NTOH_STATUS_SYNRCV;
			stream->status = NTOH_STATUS_SYNRCV;
			break;

		// Client --- ACK ---> Server
		case NTOH_STATUS_SYNRCV:

			if ( tcp->th_flags != TH_ACK )
				return NTOH_HANDSHAKE_FAILED;

			if ( ntohl(tcp->th_seq) != destination->ian + 1 )
				return NTOH_HANDSHAKE_FAILED;

			if ( ntohl(tcp->th_ack) - origin->ian != destination->next_seq )
				return NTOH_HANDSHAKE_FAILED;

			origin->status = NTOH_STATUS_ESTABLISHED;
			destination->status = NTOH_STATUS_ESTABLISHED;
			stream->status = NTOH_STATUS_ESTABLISHED;

			break;
	}

	return NTOH_OK;
}

/** @brief What to do when an incoming segment arrives to a closing connection? **/
inline static void handle_closing_connection ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , pntoh_tcp_peer_t origin , pntoh_tcp_peer_t destination , pntoh_tcp_segment_t segment, int who )
{
	pntoh_tcp_peer_t	peer = origin;
	pntoh_tcp_peer_t	side = destination;
	pntoh_tcp_stream_t	twait = 0;
	pntoh_tcp_stream_t	sptr = 0;
	ntoh_tcp_key_t		key = 0;

	send_peer_segments ( session , stream , destination , origin , origin->next_seq , 0 , 0, who );

	if ( stream->status == NTOH_STATUS_CLOSING )
	{
		if ( stream->closedby == NTOH_CLOSEDBY_CLIENT )
		{
			peer = &stream->client;
			side = &stream->server;
		}else{
			peer = &stream->server;
			side = &stream->client;
		}
	}

	/* check segment seq and ack */
	if ( ! origin->segments )
		return;

	if ( origin->segments->seq == origin->next_seq && origin->segments->ack == destination->next_seq )
	{
		/* unlink the first segment */
		segment = origin->segments;
		origin->segments = segment->next;
	}else
		return;

	/* TCP finite machine state */
	switch ( peer->status )
	{
		case NTOH_STATUS_ESTABLISHED:
			/*
			 * Expected: FIN
			 * Sender: Transits to FIN WAIT 1
			 * Receiver: Does not transits, sends ACK and transits to CLOSE WAIT
			 * */
			if ( segment->flags & TH_FIN )
				break;

			origin->status = NTOH_STATUS_FINWAIT1;
			destination->status = NTOH_STATUS_CLOSEWAIT;
			stream->status = NTOH_STATUS_CLOSING;

			if ( origin == &stream->client )
				stream->closedby = NTOH_CLOSEDBY_CLIENT;
			else if ( origin == &stream->server )
				stream->closedby = NTOH_CLOSEDBY_SERVER;

			break;

		case NTOH_STATUS_FINWAIT1:
			/*
			 * Expected:
			 * 	1) ACK
			 * 	2) FIN
			 *
			 * Receives: ACK
			 * Sender: Transits to CLOSEWAIT
			 * Receiver: FINWAIT2
			 *
			 * Receives: FIN
			 * Sender: Transits to LASTACK
			 * Receiver: Sends ACK and transits to CLOSING
			 */
			if ( segment->flags & TH_ACK )
			{
				// peer receives ACK
				if ( peer == destination )
				{
					peer->status = NTOH_STATUS_FINWAIT2;
					side->status = NTOH_STATUS_CLOSEWAIT;
				// peer sends ACK (due to a previously received FIN while being in FIN WAIT 1)
				}else
					peer->status = NTOH_STATUS_CLOSING;

			}else if ( peer == destination && ( segment->flags & TH_FIN ) )
			{
				peer->status = NTOH_STATUS_CLOSING;
				side->status = NTOH_STATUS_LASTACK;
			}

			break;

		case NTOH_STATUS_CLOSING:
			break;

		case NTOH_STATUS_FINWAIT2:
			/*
			 * Expected: FIN
			 * Sender: N/A
			 * Receiver: Sends ACK and transits to TIME WAIT
			 */
			if ( peer == destination && ( segment->flags & TH_FIN ) )
				peer->status = NTOH_STATUS_TIMEWAIT;
			else if ( peer == origin )
			{
				if ( segment->flags & TH_ACK )
				{
					peer->status = NTOH_STATUS_TIMEWAIT;
					side->status = NTOH_STATUS_CLOSED;
					stream->status = NTOH_STATUS_CLOSED;
				}else if ( segment->flags & TH_FIN )
				{
					stream->status = NTOH_STATUS_CLOSED;
					side->status = NTOH_STATUS_CLOSED;
				}
			}

			break;

		case NTOH_STATUS_TIMEWAIT:
			break;
	}

	if ( segment->flags & (TH_FIN | TH_RST) )
		origin->next_seq++;

	if ( stream->status != NTOH_STATUS_CLOSED && origin->receive )
		((pntoh_tcp_callback_t)stream->function) ( stream , origin , destination , segment , NTOH_REASON_SYNC , 0 );

	free ( segment );

	/* should we add this stream to TIMEWAIT queue? */
	if ( stream->status == NTOH_STATUS_CLOSING && IS_TIMEWAIT(stream->client , stream->server) )
	{
		HASH_FIND(hh, session->timewait, stream, sizeof(*stream), sptr);
		if ( ! sptr )
		{
			HASH_DEL(session->streams, sptr);
			sem_post ( &session->max_streams );

/*
			while ( sem_trywait ( &session->max_timewait ) != 0 )
			{
				key = htable_first ( session->timewait );
				twait = htable_remove ( session->timewait , key, 0 );
				__tcp_free_stream ( session , &twait , NTOH_REASON_SYNC , NTOH_REASON_CLOSED );
			}
*/
			HASH_ADD(hh, session->timewait, tuple, sizeof(ntoh_tcp_tuple5_t), stream);
		}
	}

	send_peer_segments ( session , stream , destination , origin , origin->next_seq , 0 , 0, who );

	return;
}

/** @brief What to do when an incoming segment arrives to an established connection? **/
inline static int handle_established_connection ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , struct tcphdr *tcp , size_t payload_len , pntoh_tcp_peer_t origin , pntoh_tcp_peer_t destination , void *udata, int who )
{
	pntoh_tcp_segment_t	segment = 0;
	unsigned long 		seq = ntohl(tcp->th_seq) - origin->isn;
	unsigned long 		ack = ntohl(tcp->th_ack) - origin->ian;

	/* only store segments with data */
	if ( payload_len > 0 )
	{
		if (stream->enable_check_nowindow) // @contrib: di3online - https://github.com/di3online
		{
			/* if we have no space */
			while ( origin->totalwin < payload_len &&
				send_peer_segments ( session , stream , origin , 
							destination , ack , 1 , 
							NTOH_REASON_NOWINDOW, who ) > 0 
			);

			/* we're in trouble */
			if ( origin->totalwin < payload_len )
				return NTOH_NO_WINDOW_SPACE_LEFT;
		}
	}

	/* creates a new segment and push it into the queue */
	segment = new_segment ( seq , ack , payload_len , tcp->th_flags , udata );
	queue_segment ( session , origin , segment );

	/* wants to close the connection ? */
	if ( ( tcp->th_flags & (TH_FIN | TH_RST) ) || origin->final_seq != 0 )
	{
		if ( ! origin->final_seq )
			origin->final_seq = seq;

        	handle_closing_connection ( session , stream , origin , destination , segment, who );
	}

	/* ACK the segments of the other side */
	if ( tcp->th_flags & TH_ACK )
		send_peer_segments ( session , stream , destination , origin , ack , 0 , 0, !who );

	return NTOH_OK;
}

/** @brief API for add an incoming segment **/
int ntoh_tcp_add_segment ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , void *ip , size_t len , void *udata )
{
	size_t			iphdr_len = 0;
	size_t			tcphdr_len = 0;
	size_t			payload_len = 0;
	struct tcphdr		*tcp = 0;
	pntoh_tcp_peer_t	origin = 0;
	pntoh_tcp_peer_t	destination = 0;
	unsigned int		tstamp = 0;
	int			ret = NTOH_OK;
	pntoh_tcp_segment_t	segment = 0;
	struct ip		*ip4hdr = (struct ip*)ip;
	struct ip6_hdr		*ip6hdr = (struct ip6_hdr*)ip;
	int			who;// @contrib: di3online - https://github.com/di3online
	unsigned int		saddr[IP6_ADDR_LEN] = {0};
	unsigned int		daddr[IP6_ADDR_LEN] = {0};

	if ( !stream || !session )
		return NTOH_ERROR_PARAMS;

	/* verify IP header */
	if ( !ip ) // no ip header
		return NTOH_INCORRECT_IP_HEADER;

	if ( ip4hdr->ip_v != 4 && ip4hdr->ip_v != 6 )
		return NTOH_INCORRECT_IP_HEADER;

	if (
		( ip4hdr->ip_v == 4 && len <= sizeof(struct ip) ) ||
		( ip4hdr->ip_v == 6 && len <= sizeof(struct ip6_hdr) )

	) // no data
		return NTOH_INCORRECT_LENGTH;

	if (
		( ip4hdr->ip_v == 4 && ( iphdr_len = 4 * ( ip4hdr->ip_hl ) ) < sizeof(struct ip) )
	) // incorrect ip header length
		return NTOH_INCORRECT_IP_HEADER_LENGTH;

        if ( ip4hdr->ip_v == 6 )
                iphdr_len = sizeof ( struct ip6_hdr );

	if (
		( ip4hdr->ip_v == 4 && len < ntohs( ip4hdr->ip_len ) ) ||
		( ip4hdr->ip_v == 6 && len < ntohs( ip6hdr->ip6_plen ) )
	 ) // incorrect capture length
		return NTOH_NOT_ENOUGH_DATA;

	if ( ip4hdr->ip_v == 4 )
	{
		saddr[0] = ip4hdr->ip_src.s_addr;
		daddr[0] = ip4hdr->ip_dst.s_addr;
	}else{
		memcpy ( (void*)saddr , (void*)&(ip6hdr->ip6_src) , IP6_ADDR_LEN );
		memcpy ( (void*)daddr , (void*)&(ip6hdr->ip6_dst) , IP6_ADDR_LEN );
	}

	/* check IP addresses */
	if ( ! (
		( !memcmp ( (void*)stream->client.addr , (void*)saddr , IP6_ADDR_LEN ) && !memcmp ( (void*)stream->server.addr , (void*)daddr , IP6_ADDR_LEN ) ) ||
		( !memcmp ( (void*)stream->client.addr , (void*)daddr , IP6_ADDR_LEN ) && !memcmp ( (void*)stream->server.addr , (void*)saddr , IP6_ADDR_LEN ) )
	) )
		return NTOH_IP_ADDRESSES_MISMATCH;
		

	if (
		( ip4hdr->ip_v == 4 && ip4hdr->ip_p != IPPROTO_TCP ) ||
		( ip4hdr->ip_v == 6 && ip6hdr->ip6_nxt != IPPROTO_TCP )
	)
		return NTOH_NOT_TCP;

	tcp = (struct tcphdr*) ( (unsigned char*)ip + iphdr_len );

	/* check TCP header */
	if ( ( tcphdr_len = tcp->th_off * 4 ) < sizeof(struct tcphdr) )
		return NTOH_INCORRECT_TCP_HEADER_LENGTH;

	if ( !tcp->th_flags || tcp->th_flags == 0xFF )
		return NTOH_INVALID_FLAGS;

	lock_access ( &stream->lock );

	/* check TCP ports */
	if ( !(
		( tcp->th_dport == stream->tuple.dport && tcp->th_sport == stream->tuple.sport ) ||
    		( tcp->th_dport == stream->tuple.sport && tcp->th_sport == stream->tuple.dport )
	))
		return NTOH_TCP_PORTS_MISMATCH;

	if ( ip4hdr->ip_v == 4 )
		payload_len = ntohs(ip4hdr->ip_len) - iphdr_len - tcphdr_len;
	else
		payload_len = ntohs(ip6hdr->ip6_plen) - tcphdr_len;

	/* get origin and destination */
	if ( !memcmp ( (void*)stream->tuple.source , (void*)saddr , IP6_ADDR_LEN ) && stream->tuple.sport == tcp->th_sport ) // @contrib: harjotgill - https://github.com/harjotgill
	{
		origin = &stream->client;
		destination = &stream->server;
		who = NTOH_SENT_BY_CLIENT;// @contrib: di3online - https://github.com/di3online
	}else{
		origin = &stream->server;
		destination = &stream->client;
		who = NTOH_SENT_BY_SERVER;// @contrib: di3online - https://github.com/di3online
	}

	get_timestamp ( tcp , tcphdr_len , &tstamp );

	/* PAWS check */
	if ( tstamp > 0 && origin->lastts > 0 )
	{
		if ( tstamp < origin->lastts )
		{
			ret = NTOH_PAWS_FAILED;
			goto exitp;
		}

		if ( ntohl(tcp->th_seq) <= origin->next_seq )
			origin->lastts = tstamp;

	}else if ( tstamp > 0 && !(origin->lastts) )
		origin->lastts = tstamp;

	if ( origin->next_seq > 0 && (origin->isn - ntohl ( tcp->th_seq ) ) < origin->next_seq )
	{
		ret = NTOH_TOO_LOW_SEQ_NUMBER;
		goto exitp;
	}

	if ( destination->next_seq > 0 && (origin->ian - ntohl(tcp->th_ack) ) < destination->next_seq )
	{
		ret = NTOH_TOO_LOW_ACK_NUMBER;
		goto exitp;
	}

	/* @todo some TCP/IP stacks implementations overloads the MSS on certain segments */
	/*if ( origin->mss > 0 && payload_len > origin->mss )
		return NTOH_SEGMENT_EXCEEDS_MSS;*/

	/* switch between connection status */
	switch ( stream->status )
	{
		case NTOH_STATUS_CLOSED:
		case NTOH_STATUS_SYNSENT:
		case NTOH_STATUS_SYNRCV:
			if ( payload_len > 0 )
			{
				ret = NTOH_HANDSHAKE_FAILED;
				goto exitp;
			}

			ret = handle_new_connection ( stream , tcp , origin ,  destination , udata );
			if ( ret == NTOH_OK )
			{
				if ( origin->receive )
				{
					if ( stream->status == NTOH_STATUS_ESTABLISHED )
						((pntoh_tcp_callback_t)stream->function) ( stream , origin , destination , 0 , NTOH_REASON_SYNC , NTOH_REASON_ESTABLISHED );
					else
						((pntoh_tcp_callback_t)stream->function) ( stream , origin , destination , 0 , NTOH_REASON_SYNC , NTOH_REASON_SYNC );
				}
			}else{
				lock_access ( &session->lock );
				delete_stream ( session , &stream , NTOH_REASON_SYNC , ret );
				unlock_access ( &session->lock );
			}

			break;

		case NTOH_STATUS_ESTABLISHED:
			ret = handle_established_connection ( session , stream , tcp , payload_len , origin , destination , udata, who );
			break;

		default:
			segment = new_segment( ntohl ( tcp->th_seq ) - origin->isn , ntohl ( tcp->th_ack ) - origin->ian , payload_len , tcp->th_flags , udata );
			queue_segment ( session , origin , segment );
			handle_closing_connection ( session , stream , origin , destination , segment, who );

			if ( stream->status == NTOH_STATUS_CLOSED )
			{
				lock_access ( &session->lock );
				__tcp_free_stream ( session , &stream , NTOH_REASON_SYNC , NTOH_REASON_CLOSED );
				unlock_access ( &session->lock );
				stream = 0;
			}
			break;
	}

	if ( ret == NTOH_OK )
	{
		if ( stream != 0 )
			gettimeofday ( & (stream->last_activ) , 0 );

		if ( payload_len == 0 )
			ret = NTOH_SYNCHRONIZING;
	}

exitp:
	if ( stream != 0 )
		unlock_access ( &stream->lock );

	return ret;
}


/* @brief resizes the hash table of a given TCP session */
int ntoh_tcp_resize_session ( pntoh_tcp_session_t session , unsigned short table , size_t newsize )
{
	if ( !session )
		return NTOH_INCORRECT_SESSION;

	return NTOH_OK;
}
