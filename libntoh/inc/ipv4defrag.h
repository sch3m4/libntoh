#ifndef __LIBNTOH_IPDF__
# define __LIBNTOH_IPDF__

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

#include <netinet/in.h>

/// macro to verify if an IP datagram is part of a fragmented datagram
#define NTOH_IPV4_IS_FRAGMENT(off)			( ( (8*(ntohs(off) & 0x1FFF)) > 0 || (ntohs(off) & 0x2000) ) && !(ntohs(off) & 0x4000) )

/** @brief Struct to generate the flow key **/
typedef struct
{
	/// source IP address
	unsigned int source;
	/// destination IP address
	unsigned int destination;
	/// Transport layer protocol
	unsigned char protocol;
	/// Identification
	unsigned short id;
} ntoh_ipv4_tuple4_t, *pntoh_ipv4_tuple4_t;

typedef unsigned int ntoh_ipv4_key_t;

/** @brief Struct to store the information of each fragment */
typedef struct _ipv4_fragment_
{
	/// pointer to the next fragment
	struct _ipv4_fragment_ *next;
	/// fragment offset
	unsigned int offset;
	/// fragment data length
	unsigned int len;
	/// fragment data
	unsigned char *data;
} ntoh_ipv4_fragment_t , *pntoh_ipv4_fragment_t;

/** @brief Struct to store the information of each IPv4 flow */
typedef struct
{
	/// flow identification data
	ntoh_ipv4_tuple4_t ident;
	/// flow key
	ntoh_ipv4_key_t key;
	/// fragments list
	pntoh_ipv4_fragment_t fragments;
	/// total amount of received data
	size_t meat;
	/// total amount of expected data
	size_t total;
	/// final fragment received?
	struct ip *final_iphdr;
	/// user defined function to receive defragmented packets
	void *function;
	/// last activity
	struct timeval last_activ;
	/// user-defined data
	void *udata;
	ntoh_lock_t lock;
} ntoh_ipv4_flow_t, *pntoh_ipv4_flow_t;

typedef htable_t ipv4_flows_table_t;
typedef phtable_t pipv4_flows_table_t;

/** @brief Structure to store global parameters */
typedef struct _ipv4_session_
{
	struct _ipv4_session_ *next;

	/// max. number of IP flows
	sem_t max_flows;
	sem_t max_fragments;
	/// hash table to store IP flows
	pipv4_flows_table_t flows;
	ntoh_lock_t lock;
	/// connection tables related
	pthread_t tID;
}ntoh_ipv4_session_t , *pntoh_ipv4_session_t ;

#ifndef MIN_IPV4_FRAGMENT_LENGTH
# define MIN_IPV4_FRAGMENT_LENGTH	576 /* min. PMTU */
#endif

#ifndef MAX_DATAGRAM_LENGTH
# define MAX_DATAGRAM_LENGTH	65535
#endif

#ifndef DEFAULT_IPV4_FRAGMENT_TIMEOUT
# define DEFAULT_IPV4_FRAGMENT_TIMEOUT		15
#endif

#ifndef DEFAULT_IPV4_MAX_FLOWS
# define DEFAULT_IPV4_MAX_FLOWS				1024
#endif

#ifndef DEFAULT_IPV4_MAX_FRAGMENTS
# define DEFAULT_IPV4_MAX_FRAGMENTS			((12*1024*1024) / sizeof(ntoh_ipv4_fragment_t))
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
 * @brief Creates a new session with independent parameters to reassemble TCP segments
 * @param max_flows Max number of allowed flows in this session
 * @param max_mem Max. amount of memory used by the session
 * @param error Returned error code
 * @return A pointer to the new session or 0 when it fails
 */
pntoh_ipv4_session_t ntoh_ipv4_new_session ( unsigned int max_flows , unsigned long max_mem , unsigned int *error );

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
 * @return A pointer to the new created flow
 */
pntoh_ipv4_flow_t ntoh_ipv4_new_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_tuple4_t tuple4 , pipv4_dfcallback_t function , void *udata , unsigned int *error);

/**
 * @brief Frees an IPv4 flow
 * @param flow IPv4 flow to be freed
 * @param reason Why has been freed the flow?
 */
void ntoh_ipv4_free_flow ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t *flow , unsigned short reason );

/**
 * @brief Adds a new IPv4 fragment to a given flow
 * @param flow Flow where the new fragment will be added
 * @param iphdr IPv4 Header of the fragment
 * @param len Length of the fragment (IPv4 header + payload)
 * @return NTOH_OK on success, or error code when it fails
 */
int ntoh_ipv4_add_fragment ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t flow , struct ip *iphdr , size_t len );

/**
 * @brief Returns the total count of flows stored in the global hash table
 * @return Total count of stored flows
 */
unsigned int ntoh_ipv4_count_flows ( pntoh_ipv4_session_t session );


#endif /* __LIBNTOH_IPDF__ */
