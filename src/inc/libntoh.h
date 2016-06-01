#ifndef __LIBNTOH_H__
# define __LIBNTOH_H__

#ifdef __cplusplus
extern "C"
{
#endif

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

#include <pthread.h>
#include <semaphore.h>

/** @brief Common return values */
#define NTOH_OK	0

/* IP defragmentation return values */
#define NTOH_IP_INCORRECT_FLOW			-1
#define NTOH_INCORRECT_LENGTH			-2
#define NTOH_INCORRECT_IP_HEADER		-3
#define NTOH_INCORRECT_IP_HEADER_LENGTH		-4
#define NTOH_NOT_IPV4				-5
#define NTOH_IP_ADDRESSES_MISMATCH		-6
#define NTOH_NOT_AN_IP_FRAGMENT			-7
#define NTOH_TOO_LOW_IP_FRAGMENT_LENGTH		-8
#define NTOH_IP_FRAGMENT_OVERRUN		-9
#define NTOH_MAX_IP_FRAGMENTS_REACHED		-10
#define NTOH_NOT_ENOUGH_DATA			-11
#define NTOH_NOT_IPV6				-12

/* TCP streams reassembly return values */
#define NTOH_INCORRECT_SESSION          	-13
#define NTOH_INCORRECT_TCP_HEADER_LENGTH	-14
#define NTOH_TCP_PORTS_MISMATCH			-15
#define NTOH_INVALID_FLAGS              	-16
#define NTOH_TOO_LOW_SEQ_NUMBER         	-17
#define NTOH_TOO_LOW_ACK_NUMBER         	-18
#define NTOH_PAWS_FAILED			-19
#define NTOH_HANDSHAKE_FAILED           	-20
#define NTOH_MAX_SYN_RETRIES_REACHED		-21
#define NTOH_MAX_SYNACK_RETRIES_REACHED		-22
#define NTOH_NO_WINDOW_SPACE_LEFT       	-23
#define NTOH_NOT_TCP				-24
#define NTOH_SYNCHRONIZING			-25
#define NTOH_NOT_INITIALIZED			-26

/* TCP streams reassembly notification cases values */
#define NTOH_REASON_HSFAILED			1
#define NTOH_REASON_ESTABLISHED			2
#define NTOH_REASON_DATA			3
#define NTOH_REASON_CLOSED			4
#define NTOH_REASON_TIMEDOUT			5
#define NTOH_REASON_EXIT			6
#define NTOH_REASON_OOO				7
#define NTOH_REASON_SEGMENT_LOST       		8 // @contrib: di3online - https://github.com/di3online
#define NTOH_REASON_MAX_SYN_RETRIES_REACHED	9
#define NTOH_REASON_MAX_SYNACK_RETRIES_REACHED	10
#define NTOH_REASON_SYNC			11
#define NTOH_REASON_NOWINDOW			12

/* IP defragmentation notification cases values */
#define NTOH_REASON_DEFRAGMENTED_DATAGRAM	13
#define NTOH_REASON_TIMEDOUT_FRAGMENTS		14

/* API errors */
#define NTOH_ERROR_NOMEM			1
#define NTOH_ERROR_NOSPACE			2
#define NTOH_ERROR_NOKEY			3
#define NTOH_ERROR_NOFUNCTION			4
#define NTOH_ERROR_INVALID_TUPLE5		5
#define NTOH_ERROR_PARAMS			6
#define NTOH_ERROR_INIT				7

typedef struct
{
	pthread_mutex_t	mutex;
	pthread_cond_t	pcond;
	int		use;
} ntoh_lock_t , *pntoh_lock_t;

/** @brief Header files */
#include "common.h"
#include "ipv4defrag.h"
#include "ipv6defrag.h"
#include "tcpreassembly.h"

/**
 * @brief Returns library version
 * @return The version of the library
 */
const char* ntoh_version ( void );

/**
 * @brief Returns the description string of ntoh_add_tcpsegment and ntoh_add_ipv4fragment
 * @param val Value returned by those functions
 * @return Description string or 0 if val is not found
 */
const char* ntoh_get_retval_desc ( int val );

/**
 * @brief Returns the description string about why a segment/fragment has been sent to the user
 * @param val
 * @return Description string or 0 if val is not found
 */
const char* ntoh_get_reason ( int val );

/**
 * @brief Returns the description of an error
 * @param val Error code
 * @returns Description string or 0 if val is not found
 */
const char* ntoh_get_errdesc ( unsigned int val );

/**
 * @brief Initializes the library (TCP and IPv4)
 */
void ntoh_init ( void );

/**
 * @brief Releases all resources
 */
void ntoh_exit ( void );

#ifdef __cplusplus
}
#endif

#endif /*__LIBNTOH_H__ */
