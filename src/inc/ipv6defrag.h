#ifndef __LIBNTOH_IP6DF__
# define __LIBNTOH_IP6DF__

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
#include <netinet/ip6.h>

#include <uthash.h>

#define NTOH_IPV6_IS_FRAGMENT(val)  (((struct ip6_hdr*)val)->ip6_nxt==IPPROTO_FRAGMENT && \
                                     ( \
                                      (ntohs(((struct ip6_frag *)((unsigned char*)val+sizeof(struct ip6_hdr)))->ip6f_offlg) & IP6F_OFF_MASK)>0 || \
                                      (ntohs(((struct ip6_frag *)((unsigned char*)val+sizeof(struct ip6_hdr)))->ip6f_offlg & IP6F_MORE_FRAG)>0) \
                                      ))

/** @brief Struct to generate the flow key **/
typedef struct
{
	/// source IP address
	unsigned char	source[16];
	/// destination IP address
	unsigned char	destination[16];
	/// Transport layer protocol
	unsigned char	protocol;
	/// Identification
	unsigned int	id;
} ntoh_ipv6_tuple4_t, *pntoh_ipv6_tuple4_t;

typedef unsigned int ntoh_ipv6_key_t;

/** @brief Struct to store the information of each fragment */
typedef struct _ipv6_fragment_
{
	/// pointer to the next fragment
	struct _ipv6_fragment_	*next;
	/// fragment offset
	unsigned int 		offset;
	/// fragment data length
	unsigned int 		len;
	/// fragment data
	unsigned char 		*data;
} ntoh_ipv6_fragment_t , *pntoh_ipv6_fragment_t;

/** @brief Struct to store the information of each IPv6 flow */
typedef struct
{
	/// flow identification data
	ntoh_ipv6_tuple4_t 	ident;
	/// fragments list
	pntoh_ipv6_fragment_t 	fragments;
	/// total amount of received data
	size_t 			meat;
	/// total amount of expected data
	size_t 			total;
	/// final fragment received?
	struct ip6_hdr		*final_iphdr;
	/// user defined function to receive defragmented packets
	void 			*function;
	/// last activity
	struct timeval 		last_activ;
	/// user-defined data
	void 			*udata;
	ntoh_lock_t 		lock;
	UT_hash_handle		hh;
} ntoh_ipv6_flow_t, *pntoh_ipv6_flow_t;

/** @brief Structure to store global parameters */
typedef struct _ipv6_session_
{
	struct _ipv6_session_ 	*next;

	/// max. number of IP flows
	sem_t 			max_flows;
	sem_t 			max_fragments;
	/// hash table to store IP flows
	pntoh_ipv6_flow_t	flows;
	/// connection tables related
	pthread_t 		tID;
	ntoh_lock_t 		lock;
}ntoh_ipv6_session_t , *pntoh_ipv6_session_t;

typedef struct
{
        unsigned short          init;
        pntoh_ipv6_session_t	sessions_list;
        ntoh_lock_t             lock;
} ntoh_ipv6_params_t , *pntoh_ipv6_params_t;

/// min. PMTU
#ifndef MIN_IPV6_FRAGMENT_LENGTH
# define MIN_IPV6_FRAGMENT_LENGTH	1280
#endif

/// max. IPv6 datagram fragment length
#ifndef MAX_IPV6_DATAGRAM_LENGTH
# define MAX_IPV6_DATAGRAM_LENGTH	4294967295UL   // max size of jumbograms (using hop-by-hop options header)
#endif

/// IPv6 fragment timeout
#ifndef DEFAULT_IPV6_FRAGMENT_TIMEOUT
# define DEFAULT_IPV6_FRAGMENT_TIMEOUT	15
#endif

/// max. IPv6 allowed flows
#ifndef DEFAULT_IPV6_MAX_FLOWS
# define DEFAULT_IPV6_MAX_FLOWS		1024
#endif

/// max. IPv6 allowed fragments
#ifndef DEFAULT_IPV6_MAX_FRAGMENTS
# define DEFAULT_IPV6_MAX_FRAGMENTS	((12*1024*1024) / sizeof(ntoh_ipv6_fragment_t))
#endif

typedef void(*pipv6_dfcallback_t) ( pntoh_ipv6_flow_t , pntoh_ipv6_tuple4_t , unsigned char* , size_t , unsigned short );

/**
 * @brief Initializes the IPv6 defragmentation
 */
void ntoh_ipv6_init ( void );

/**
 * @brief Flush all IPv6 sessions and release all resources
 */
void ntoh_ipv6_exit ( void );

/**
 * @brief Releases all resources used by an IPv6 session
 * @param session Session to be released
 */
void ntoh_ipv6_free_session ( pntoh_ipv6_session_t session );

/**
 * @brief Creates a new session with independent parameters to reassemble TCP segments
 * @param max_flows Max number of allowed flows in this session
 * @param max_mem Max. amount of memory used by the session
 * @param error Returned error code
 * @return A pointer to the new session or 0 when it fails
 */
pntoh_ipv6_session_t ntoh_ipv6_new_session ( unsigned int max_flows , unsigned long max_mem , unsigned int *error );

/**
 * @brief resizes the hash table of a given IPv4 session
 * @param IPv4 Session
 * @param size The new size of the hash table
 * @return NTOH_OK on success or the corresponding error code
 *
**/
int ntoh_ipv6_resize_session ( pntoh_ipv6_session_t session , size_t size );

/**
 * @brief Finds an IP flow
 * @param tuple4 Flow information
 * @return Pointer to the flow on success or 0 when fails
 */
pntoh_ipv6_flow_t ntoh_ipv6_find_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_tuple4_t tuple4 );

/**
 * @brief Adds a new IPv6 flow
 * @param tuple4 Flow information
 * @param function User defined function to receive defragmented datagrams
 * @param count_max Max. fragments allowed
 * @param udata User defined data associated with this flow
 * @return A pointer to the new created flow
 */
pntoh_ipv6_flow_t ntoh_ipv6_new_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_tuple4_t tuple4 , pipv6_dfcallback_t function , void *udata , unsigned int *error);

/**
 * @brief Frees an IPv6 flow
 * @param flow IPv6 flow to be freed
 * @param reason Why has been freed the flow?
 */
void ntoh_ipv6_free_flow ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t *flow , unsigned short reason );

/**
 * @brief Adds a new IPv6 fragment to a given flow
 * @param flow Flow where the new fragment will be added
 * @param iphdr IPv6 Header of the fragment
 * @return NTOH_OK on success, or error code when it fails
 */
int ntoh_ipv6_add_fragment ( pntoh_ipv6_session_t session , pntoh_ipv6_flow_t flow , struct ip6_hdr *iphdr );

/**
 * @brief Returns the total count of flows stored in the global hash table
 * @return Total count of stored flows
 */
unsigned int ntoh_ipv6_count_flows ( pntoh_ipv6_session_t session );

/**
 * @brief Gets the size of the flows table (max allowed flows)
 * @param session IPv6 Session
 * @return The max. amount of IPv6 flows that can be stored , or zero on error
**/
unsigned int ntoh_ipv6_get_size ( pntoh_ipv6_session_t session );

/**
 * @brief Gets the tuple4 of a IPv6 flow
 * @param ip Pointer to the IPv6 header
 * @param tuple Pointer to the output tuple4 struct
 * @return NTOH_OK on success or the corresponding error code
 */
unsigned int ntoh_ipv6_get_tuple4 ( struct ip6_hdr *ip , pntoh_ipv6_tuple4_t tuple );

#endif /* __LIBNTOH_IP6DF__ */
