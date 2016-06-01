#ifndef __LIBNTOH_IP4DF__
# define __LIBNTOH_IP4DF__

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

#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <uthash.h>

/// macro to verify if an IP datagram is part of a fragmented datagram
#define NTOH_IPV4_IS_FRAGMENT(off)	( ( (8*(ntohs(off) & 0x1FFF)) > 0 || (ntohs(off) & 0x2000) ) && !(ntohs(off) & 0x4000) )

/** @brief Struct to generate the flow key **/
typedef struct
{
	/// source IP address
	unsigned int	source;
	/// destination IP address
	unsigned int	destination;
	/// Transport layer protocol
	unsigned char	protocol;
	/// Identification
	unsigned short	id;
} ntoh_ipv4_tuple4_t, *pntoh_ipv4_tuple4_t;

typedef unsigned int ntoh_ipv4_key_t;

/** @brief Struct to store the information of each fragment */
typedef struct _ipv4_fragment_
{
	/// pointer to the next fragment
	struct _ipv4_fragment_		*next;
	/// fragment offset
	unsigned int 			offset;
	/// fragment data length
	unsigned int 			len;
	/// fragment data
	unsigned char 			*data;
} ntoh_ipv4_fragment_t , *pntoh_ipv4_fragment_t;

/** @brief Struct to store the information of each IPv4 flow */
typedef struct
{
	/// flow identification data
	ntoh_ipv4_tuple4_t 		ident;
	/// fragments list
	pntoh_ipv4_fragment_t 		fragments;
	/// total amount of received data
	size_t 				meat;
	/// total amount of expected data
	size_t 				total;
	/// final fragment received?
	struct ip 			*final_iphdr;
	/// user defined function to receive defragmented packets
	void 				*function;
	/// last activity
	struct timeval 			last_activ;
	/// user-defined data
	void 				*udata;
	ntoh_lock_t 			lock;
	UT_hash_handle			hh;
} ntoh_ipv4_flow_t, *pntoh_ipv4_flow_t;

/** @brief Structure to store global parameters */
typedef struct _ipv4_session_
{
	struct _ipv4_session_ 		*next;

	/// max. number of IP flows
	sem_t 				max_flows;
	sem_t 				max_fragments;
	/// hash table to store IP flows
	pntoh_ipv4_flow_t		flows;
	/// connection tables related
	pthread_t 			tID;
	ntoh_lock_t 			lock;
}ntoh_ipv4_session_t , *pntoh_ipv4_session_t;

typedef struct
{
        unsigned short          init;
        pntoh_ipv4_session_t	sessions_list;
        ntoh_lock_t             lock;
} ntoh_ipv4_params_t , *pntoh_ipv4_params_t;

/// min. PMTU
#ifndef MIN_IPV4_FRAGMENT_LENGTH
# define MIN_IPV4_FRAGMENT_LENGTH	576
#endif

/// max. IPv4 datagram fragment length
#ifndef MAX_IPV4_DATAGRAM_LENGTH
# define MAX_IPV4_DATAGRAM_LENGTH	65535
#endif

/// IPv4 fragment timeout
#ifndef DEFAULT_IPV4_FRAGMENT_TIMEOUT
# define DEFAULT_IPV4_FRAGMENT_TIMEOUT	15
#endif

/// max. IPv4 allowed flows
#ifndef DEFAULT_IPV4_MAX_FLOWS
# define DEFAULT_IPV4_MAX_FLOWS		1024
#endif

/// max. IPv4 allowed fragments
#ifndef DEFAULT_IPV4_MAX_FRAGMENTS
# define DEFAULT_IPV4_MAX_FRAGMENTS	((12*1024*1024) / sizeof(ntoh_ipv4_fragment_t))
#endif

typedef void(*pipv4_dfcallback_t) ( pntoh_ipv4_flow_t , pntoh_ipv4_tuple4_t , unsigned char* , size_t , unsigned short );

/**
 * @brief Initializes the IPv4 defragmentation
 */
void ntoh_ipv4_init ( void );

/**
 * @brief Flush all IPv4 sessions and release all resources
 */
void ntoh_ipv4_exit ( void );

/**
 * @brief Releases all resources used by an IPv4 session
 * @param session Session to be released
 */
void ntoh_ipv4_free_session ( pntoh_ipv4_session_t session );

/**
 * @brief Creates a new session with independent parameters to defragment IPv4
 * @param max_flows Max number of allowed flows in this session
 * @param max_mem Max. amount of memory used by the session
 * @param error Returned error code
 * @return A pointer to the new session or 0 when it fails
 */
pntoh_ipv4_session_t ntoh_ipv4_new_session ( unsigned int max_flows , unsigned long max_mem , unsigned int *error );

/**
 * @brief resizes the hash table of a given IPv4 session
 * @param IPv4 Session
 * @param size The new size of the hash table
 * @return NTOH_OK on success or the corresponding error code
 *
**/
int ntoh_ipv4_resize_session ( pntoh_ipv4_session_t session , size_t size );

/**
 * @brief Finds an IP flow
 * @param tuple4 Flow information
 * @return Pointer to the flow on success or 0 when fails
 */
pntoh_ipv4_flow_t ntoh_ipv4_find_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_tuple4_t tuple4 );

/**
 * @brief Adds a new IPv4 flow
 * @param tuple4 Flow information
 * @param function User defined function to receive defragmented datagrams
 * @param count_max Max. fragments allowed
 * @param udata User defined data associated with this flow
 * @param error Returned error code
 * @return A pointer to the new created flow
 */
pntoh_ipv4_flow_t ntoh_ipv4_new_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_tuple4_t tuple4 , pipv4_dfcallback_t function , void *udata , unsigned int *error);

/**
 * @brief Frees an IPv4 flow
 * @param session Pointer to the IPv4 session
 * @param flow IPv4 flow to be released
 * @param reason Value to be sent to the user-defined callback. Why has been freed the flow?
 */
void ntoh_ipv4_free_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t *flow , unsigned short reason );

/**
 * @brief Adds a new IPv4 fragment to a given flow
 * @param session Pointer to the IPv4 session
 * @param flow Flow where the new fragment will be added
 * @param iphdr IPv4 Header of the fragment
 * @return NTOH_OK on success, or error code when it fails
 */
int ntoh_ipv4_add_fragment ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t flow , struct ip *iphdr );

/**
 * @brief Returns the total count of flows stored in the global hash table
 * @return Total count of stored flows
 */
unsigned int ntoh_ipv4_count_flows ( pntoh_ipv4_session_t session );

/**
 * @brief Gets the size of the flows table (max allowed flows)
 * @param session IPv4 Session
 * @return The max. amount of IPv4 flows that can be stored , or zero on error
**/
unsigned int ntoh_ipv4_get_size ( pntoh_ipv4_session_t session );

/**
 * @brief Gets the tuple4 of a IPv4 flow
 * @param ip Pointer to the IPv4 header
 * @param tuple Pointer to the output tuple4 struct
 * @return NTOH_OK on success or the corresponding error code
 */
unsigned int ntoh_ipv4_get_tuple4 ( struct ip *ip , pntoh_ipv4_tuple4_t tuple );

#endif /* __LIBNTOH_IP4DF__ */
