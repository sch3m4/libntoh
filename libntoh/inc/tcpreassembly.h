#ifndef __LIBNTOH_TCPRS_H__
# define __LIBNTOH_TCPRS_H__

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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>

/** @brief connection status **/
enum _ntoh_tcp_status_
{
	NTOH_STATUS_CLOSED = 0,
	NTOH_STATUS_LISTEN,
	NTOH_STATUS_SYNSENT,
	NTOH_STATUS_SYNRCV,
	NTOH_STATUS_ESTABLISHED,
	NTOH_STATUS_CLOSING,
	NTOH_STATUS_CLOSEWAIT,
	NTOH_STATUS_FINWAIT1,
	NTOH_STATUS_FINWAIT2,
	NTOH_STATUS_LASTACK,
	NTOH_STATUS_TIMEWAIT
};

/** @brief who closed the connection? **/
enum tcprs_who_closed
{
	NTOH_CLOSEDBY_UNKNOWN = 0,
	NTOH_CLOSEDBY_CLIENT,
	NTOH_CLOSEDBY_SERVER
};

/** @brief key to identify connections **/
typedef unsigned int ntoh_tcp_key_t;

/** @brief data to generate the connection key **/
typedef struct
{
	///source address
	unsigned int source;
	///destination address
	unsigned int destination;
	///source port
	unsigned short sport;
	///destination port
	unsigned short dport;
} ntoh_tcp_tuple4_t, *pntoh_tcp_tuple4_t;

/** @brief data sent to user-function **/
typedef struct _tcp_segment_
{
	struct _tcp_segment_ *next;
	///SEQ number
	unsigned long seq;
	///ACK number
	unsigned long ack;
	///flags
	unsigned char flags;
	///payload length
	unsigned int payload_len;
	///segment origin
	unsigned short origin;
	///TCP timestamp
	struct timeval tv;
	///user provided data
	void *user_data;
} ntoh_tcp_segment_t, *pntoh_tcp_segment_t;

/** @brief peer information **/
typedef struct
{
	///IP address
	unsigned int addr;
	///connection port
	unsigned short port;
	///first SEQ. number
	unsigned long isn;
	///first ACK. number
	unsigned long ian;
	///NEXT SEQ. number
	unsigned long next_seq;
	///TH_FIN | TH_RST sequence
	unsigned long final_seq;
	///TCP window size
	unsigned int wsize;
	///peer status
	unsigned int status;
	///segments list
	pntoh_tcp_segment_t segments;
	///Max. Segment Size
	unsigned int mss;
	///Selective ACK.
	unsigned int sack;
	///window scale factor
	unsigned int wscale;
	//total window size
	unsigned long totalwin;
	// last ts
	unsigned int lastts;
} ntoh_tcp_peer_t, *pntoh_tcp_peer_t;

/** @brief connection data **/
typedef struct _tcp_stream_
{
	struct _tcp_stream_ *next;

	///data to generate the key to identify the connection
	ntoh_tcp_tuple4_t tuple;
	///client data
	ntoh_tcp_peer_t client;
	///server data
	ntoh_tcp_peer_t server;
	///connection key
	ntoh_tcp_key_t key;
	///connection status
	unsigned int status;
	///who closed the connection
	unsigned short closedby;
	///user-defined function to receive data
	void *function;
	///last activity
	struct timeval last_activ;
	///max. allowed SYN retries
	unsigned int syn_retries;
	///max. allowed SYN/ACK retries
	unsigned int synack_retries;
	///user-defined data linked to this stream
	void *udata;
	ntoh_lock_t	lock;
} ntoh_tcp_stream_t, *pntoh_tcp_stream_t;

typedef htable_t tcprs_streams_table_t;
typedef phtable_t ptcprs_streams_table_t;

/** @brief TCP session data **/
typedef struct _tcp_session_
{
		struct _tcp_session_ *next;

        /* max. streams */
        sem_t max_streams;
        sem_t max_timewait;

        /* connections hash table */
        ptcprs_streams_table_t streams;

        /* TIME-WAIT connections */
        ptcprs_streams_table_t timewait;

        ntoh_lock_t	lock;
        pthread_t tID;
} ntoh_tcp_session_t , *pntoh_tcp_session_t;

typedef void(*pntoh_tcp_callback_t) ( pntoh_tcp_stream_t , pntoh_tcp_peer_t , pntoh_tcp_peer_t , pntoh_tcp_segment_t , int, int );

/** @brief max allowed connections **/
#ifndef DEFAULT_TCP_MAX_STREAMS
# define DEFAULT_TCP_MAX_STREAMS 1024
#endif

/** @brief max SYN retries **/
#ifndef DEFAULT_TCP_SYN_RETRIES
# define DEFAULT_TCP_SYN_RETRIES    5
#endif

/** @brief max SYN/ACK retries **/
#ifndef DEFAULT_TCP_SYNACK_RETRIES
# define DEFAULT_TCP_SYNACK_RETRIES 5
#endif

/** @brief SYN/ACK timeout **/
#ifndef DEFAULT_TCP_SYNSENT_TIMEOUT
# define DEFAULT_TCP_SYNSENT_TIMEOUT    5
#endif

/** @brief ACK -> SYN timeout **/
#ifndef DEFAULT_TCP_SYNRCV_TIMEOUT
# define DEFAULT_TCP_SYNRCV_TIMEOUT    5
#endif

/** @brief max. idle time for established connections **/
#ifndef DEFAULT_TCP_ESTABLISHED_TIMEOUT
# define DEFAULT_TCP_ESTABLISHED_TIMEOUT    60
#endif

/** @brief max. idle time for "closed" connections **/
#ifndef DEFAULT_TCP_FINWAIT2_TIMEOUT
# define DEFAULT_TCP_FINWAIT2_TIMEOUT   60
#endif

/** @brief Default timeout for TIMEWAIT tcp connections **/
#ifndef DEFAULT_TCP_TIMEWAIT_TIMEOUT
# define DEFAULT_TCP_TIMEWAIT_TIMEOUT   2*DEFAULT_TCP_ESTABLISHED_TIMEOUT
#endif

/** @brief Macro to set the default TIMEWAIT for new connections **/
#ifndef DEFAULT_TCP_MAX_TIMEWAIT_STREAMS
# define DEFAULT_TCP_MAX_TIMEWAIT_STREAMS(max)   (max>0?max/3:DEFAULT_TCP_MAX_STREAMS/3)
#endif

/**
 * @brief Initializes all needed resources for TCP reassembly
 */
void ntoh_tcp_init ( void );

/**
 * @brief Releases all resources used by TCP reassembly
 */
void ntoh_tcp_exit ( void );

/**
 * @brief Creates a new session with independent parameters to reassemble TCP segments
 * @param max_streams Max number of allowed streams in this session
 * @param max_timewait Max idle time fo TIME-WAIT connections (global)
 * @param error Returned error code
 * @return A pointer to the new session or 0 when it fails
 */
pntoh_tcp_session_t ntoh_tcp_new_session ( unsigned int max_streams , unsigned int max_timewait , unsigned int *error );

/**
 * @brief Releases all resources used by a session
 * @param session Session to be released
 */
void ntoh_tcp_free_session ( pntoh_tcp_session_t session );

/**
 * @brief Frees a given TCP stream
 * @param session Pointer to the session
 * @param stream Pointer to the stream
 * @param reason Value to be sent to the user defined function
 * @param extra Value to be sent to the user defined function
 */
void ntoh_tcp_free_stream ( pntoh_tcp_session_t session , pntoh_tcp_stream_t *stream , int reason , int extra );

/**
 * @brief Finds a TCP stream
 * @param session TCP Session
 * @param tuple4 Stream information
 * @return Pointer to the stream on success or 0 when fails
 */
pntoh_tcp_stream_t ntoh_tcp_find_stream ( pntoh_tcp_session_t session , pntoh_tcp_tuple4_t tuple4 );

/**
 * @brief Adds a new TCP stream
 * @param session TCP Session
 * @param tuple4 Stream information
 * @param function User defined function to receive the segments of this stream
 * @param udata User-defined data to be linked to the new stream
 * @param error Returned error code
 * @return A pointer to the new stream on success or 0 when fails
 */
pntoh_tcp_stream_t ntoh_tcp_new_stream ( pntoh_tcp_session_t session , pntoh_tcp_tuple4_t tuple4 , pntoh_tcp_callback_t function , void *udata , unsigned int *error );

/**
 * @brief Returns the total count of TCP streams stored in the global hash table
 * @param session TCP Session
 * @return Total count of stored streams
 */
unsigned int ntoh_tcp_count_streams ( pntoh_tcp_session_t session );

/**
 * @brief Adds a new segment to a given stream
 * @param session TCP Session
 * @param stream Pointer to the stream
 * @param ip_hdr IP Header
 * @param len Total length of this segment
 * @param udata Used data associated with this segment
 * @return NTOH_OK on success or the corresponding error code
 */
int ntoh_tcp_add_segment ( pntoh_tcp_session_t session , pntoh_tcp_stream_t stream , struct ip *ip , size_t len , void *udata );

/**
 * @brief Get the status string of a stream/peer
 * @param status Status id
 * @return Status string on success or 0 when fails
 */
const char *ntoh_tcp_get_status ( unsigned int status );


#endif /* __LIBNTOH_TCPRS_H__ */
