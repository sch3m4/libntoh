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

/**
 * @author Chema Garcia (aka sch3m4) <chema@safetybits.net || sch3m4@brutalsec.net>
 * @mainpage https://github.com/sch3m4/libntoh/
 * @version 0.4a
 */

#include <libntoh.h>

#define VERSION "0.4a"

static const char retval_descriptions[][48] =
{
		/* ntoh_add_ipv(4|6)fragment */
		"Success" ,
		"Incorrect IP flow" ,
		"Incorrect length" ,
		"Incorrect IP header" ,
		"Incorrect IP header length" ,
		"Not an IPv4 datagram" ,
		"IP addresses mismatch" ,
		"Not an IPv4 fragment" ,
		"Too small IP fragment",
		"Fragment overrun" ,
		"Max. IP fragments reached" ,
		"Not enough data",
		"Not an IPv6 fragment",

		/* ntoh_add_tcpsegment return values description */
		"Incorrect session" ,
		"Incorrect TCP header length" ,
		"TCP ports mismatch",
		"Invalid flags" ,
		"Too low seq. number" ,
		"Too low ack. number" ,
		"PAWS check failed",
		"TCP handshake failed" ,
		"Max. SYN retries reached" ,
		"Max. SYN/ACK retries reached" ,
		"No TCP window space left",
		"Not a TCP segment",
		"Synchronizing connection",
		"Library not initialized"
};

/** @brief reason description strings **/
static const char reason_descriptions[][30]=
{
		/* TCP */
		"Handshake failed" ,
		"Established" ,
		"Data" ,
		"Closed" ,
		"Timedout" ,
		"Exiting" ,
		"Out-Of-Order" ,
		"Previous segment lost", // about
		"Max. SYN retries reached" ,
		"Max. SYN/ACK retries reached" ,
		"Synchronization",
		"No window space left",

		/* IP */
		"Defragmented IP datagram",
		"Timeout expired"
};

/* API errors */
static const char api_errors[][25] = {
		"No error",
		"Cannot allocate memory",
		"No space for add streams",
		"Null key",
		"Invalid function pointer",
		"Invalid tuple4 field(s)",
		"Invalid parameter(s)",
		"Library not initialized"
};

const char* ntoh_version ( void )
{
	return (const char*) VERSION;
}

const char* ntoh_get_retval_desc ( int val )
{
	unsigned int pos = (unsigned int)(val * (-1));

	if ( pos > (sizeof(retval_descriptions) / sizeof(*retval_descriptions) ) )
		return 0;

	return retval_descriptions[pos];
}

const char* ntoh_get_reason ( int val )
{
	if ( !val || val > (sizeof(reason_descriptions) / sizeof(*reason_descriptions)) )
		return 0;

	return reason_descriptions[val - 1];
}

const char* ntoh_get_errdesc ( unsigned int val )
{
	if ( val > (sizeof(api_errors) / sizeof(*api_errors)) )
		return 0;

	return api_errors[val];
}

void ntoh_init ( void )
{
	ntoh_tcp_init();
	ntoh_ipv4_init();
	ntoh_ipv6_init();

	return;
}

void ntoh_exit ( void )
{
	ntoh_tcp_exit();
	ntoh_ipv4_exit();
	ntoh_ipv6_exit();

	return;
}
