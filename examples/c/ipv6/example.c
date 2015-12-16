/********************************************************************************
 * Copyright (c) 2014, Chema Garcia                                             *
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

/*
 * This example defragments IPv6 datagrams and once it's completed shows the hex values of the final IPv6 header and data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>

#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif

#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <libntoh.h>

#define RECV_CLIENT	1
#define RECV_SERVER	2

/* capture handle */
pcap_t			*handle = 0;
pntoh_ipv6_session_t	ipv6_session = 0;
unsigned short		receive = 0;

/**
 * @brief Exit function (closes the capture handle and releases all resource from libntoh)
 */
void shandler ( int sign )
{
	if ( sign != 0 )
		signal ( sign , &shandler );

	pcap_close( handle );

	ntoh_exit();

	fprintf( stderr, "\n\n[+] Capture finished!\n" );
	exit( sign );
}

/**
 * @brief Returns the name of a protocol
 */
inline char *get_proto_description ( unsigned short proto )
{
	switch ( proto )
	{
		case IPPROTO_ICMP:
			return "ICMP";

		case IPPROTO_TCP:
			return "TCP";

		case IPPROTO_UDP:
			return "UDP";

		case IPPROTO_IGMP:
			return "IGMP";

		case IPPROTO_IPV6:
			return "IPv6";

		case IPPROTO_FRAGMENT:
			return "IPv6 Fragment";

		default:
			return "Undefined";
	}
}

/**
 * @brief Sends a IPv6 fragment to libntoh
 */
void send_ipv6_fragment ( struct ip6_hdr *iphdr , pipv6_dfcallback_t callback )
{
	ntoh_ipv6_tuple4_t 	ipt4;
	pntoh_ipv6_flow_t 	flow;
	size_t			total_len;
	int 			ret;
	unsigned int		error;

	total_len = ntohs( iphdr->ip6_plen );

	ntoh_ipv6_get_tuple4 ( iphdr , &ipt4 );

	if ( ! ( flow = ntoh_ipv6_find_flow( ipv6_session , &ipt4 ) ) )
		if ( ! (flow = ntoh_ipv6_new_flow( ipv6_session , &ipt4, callback, 0 , &error )) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new IPv6 flow: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}

	if ( ( ret = ntoh_ipv6_add_fragment( ipv6_session , flow, iphdr, total_len ) ) != NTOH_OK )
		fprintf( stderr, "\n[e] Error %d adding IPv6: %s", ret, ntoh_get_retval_desc( ret ) );

	return;
}

/* IPv6 Callback */
void ipv6_callback ( pntoh_ipv6_flow_t flow , pntoh_ipv6_tuple4_t tuple , unsigned char *data , size_t len , unsigned short reason )
{
	unsigned int i = 0;

	fprintf( stderr, "\n\n[i] Got an IPv6 datagram! (%s - %d) %s --> ", ntoh_get_reason(reason) , reason , inet_ntoa( * (struct in_addr*) &tuple->source ) );
	fprintf( stderr, "%s | %zu/%zu bytes - Key: %04x - ID: %02x - Proto: %d (%s)\n\n", inet_ntoa( *(struct in_addr*) &tuple->destination ), len, flow->total , flow->key, ntohs( tuple->id ), tuple->protocol, get_proto_description( tuple->protocol ) );

	for ( i = 0; i < flow->total ; i++ )
		fprintf( stderr, "%02x ", data[i] );

	fprintf( stderr, "\n" );

	return;
}

int main ( int argc , char *argv[] )
{
	/* parameters parsing */
	int c;

	/* pcap */
	char 				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program 		fp;
	char 				filter_exp[] = "ip6";
	char 				*source = 0;
	char 				*filter = filter_exp;
	const unsigned char		*packet = 0;
	struct pcap_pkthdr		header;

	/* packet dissection */
	struct ip6_hdr	*ip;
	unsigned int	error;

	/* extra */
	unsigned int ipf;

	fprintf( stderr, "\n###########################" );
	fprintf( stderr, "\n#     libntoh Example     #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n# Written by Chema Garcia #" );
	fprintf( stderr, "\n# ----------------------- #" );
	fprintf( stderr, "\n#  http://safetybits.net  #" );
	fprintf( stderr, "\n#   chema@safetybits.net  #" );
	fprintf( stderr, "\n###########################\n" );

	fprintf( stderr, "\n[i] libntoh version: %s\n", ntoh_version() );

	if ( argc < 3 )
	{
		fprintf( stderr, "\n[+] Usage: %s <options>\n", argv[0] );
		fprintf( stderr, "\n+ Options:" );
		fprintf( stderr, "\n\t-i | --iface <val> -----> Interface to read packets from" );
		fprintf( stderr, "\n\t-f | --file <val> ------> File path to read packets from" );
		fprintf( stderr, "\n\t-F | --filter <val> ----> Capture filter (should include \"ipv6\")" );
		fprintf( stderr, "\n\t-c | --client ----------> Receive client data");
		fprintf( stderr, "\n\t-s | --server ----------> Receive server data\n\n");
		exit( 1 );
	}

	/* check parameters */
	while ( 1 )
	{
		int option_index = 0;
		static struct option long_options[] =
		{
		{ "iface" , 1 , 0 , 'i' } ,
		{ "file" , 1 , 0 , 'f' } ,
		{ "filter" , 1 , 0 , 'F' } ,
		{ "client" , 0 , 0 , 'c' },
		{ "server" , 0 , 0 , 's' },
		{ 0 , 0 , 0 , 0 } };

		if ( ( c = getopt_long( argc, argv, "i:f:F:cs", long_options, &option_index ) ) < 0 )
			break;

		switch ( c )
		{
			case 'i':
				source = optarg;
				handle = pcap_open_live( optarg, 65535, 1, 0, errbuf );
				break;

			case 'f':
				source = optarg;
				handle = pcap_open_offline( optarg, errbuf );
				break;

			case 'F':
				filter = optarg;
				break;

			case 'c':
				receive |= RECV_CLIENT;
				break;

			case 's':
				receive |= RECV_SERVER;
				break;
		}
	}

	if ( !receive )
		receive = (RECV_CLIENT | RECV_SERVER);

	if ( !handle )
	{
		fprintf( stderr, "\n[e] Error loading %s: %s\n", source, errbuf );
		exit( -1 );
	}

	if ( pcap_compile( handle, &fp, filter, 0, 0 ) < 0 )
	{
		fprintf( stderr, "\n[e] Error compiling filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -2 );
	}

	if ( pcap_setfilter( handle, &fp ) < 0 )
	{
		fprintf( stderr, "\n[e] Cannot set filter \"%s\": %s\n\n", filter, pcap_geterr( handle ) );
		pcap_close( handle );
		exit( -3 );
	}
	pcap_freecode( &fp );

	/* verify datalink */
	if ( pcap_datalink( handle ) != DLT_EN10MB )
	{
		fprintf ( stderr , "\n[e] libntoh is independent from link layer, but this example only works with ethernet link layer\n");
		pcap_close ( handle );
		exit ( -4 );
	}

	fprintf( stderr, "\n[i] Source: %s / %s", source, pcap_datalink_val_to_description( pcap_datalink( handle ) ) );
	fprintf( stderr, "\n[i] Filter: %s", filter );

	fprintf( stderr, "\n[i] Receive data from client: ");
	if ( receive & RECV_CLIENT )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	fprintf( stderr, "\n[i] Receive data from server: ");
	if ( receive & RECV_SERVER )
		fprintf( stderr , "Yes");
	else
		fprintf( stderr , "No");

	signal( SIGINT, &shandler );
	signal( SIGTERM, &shandler );

	/*******************************************/
	/** libntoh initialization process starts **/
	/*******************************************/

	ntoh_ipv6_init ();

	if ( ! (ipv6_session = ntoh_ipv6_new_session ( 0 , 0 , &error )) )
	{
		fprintf ( stderr , "\n[e] Error %d creating IPv6 session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -6 );
	}

	fprintf ( stderr , "\n[i] Max. IPv6 flows allowed: %d\n\n" , ntoh_ipv6_get_size ( ipv6_session ) );

	/* capture starts */
	while ( ( packet = pcap_next( handle, &header ) ) != 0 )
	{
		/* get packet headers */
		ip = (struct ip6_hdr*) ( packet + sizeof ( struct ether_header ) );

		/* it is an IPv6 fragment */
		if ( NTOH_IPV6_IS_FRAGMENT(ip) )
			send_ipv6_fragment ( ip , &ipv6_callback );
	}

	ipf = ntoh_ipv6_count_flows ( ipv6_session );

	/* no streams left */
	if ( ipf > 0 )
	{
		fprintf( stderr, "\n\n[+] There are currently %i IPv6 flow(s). You can wait them to get closed or press CTRL+C\n" , ipf );
		pause();
	}

	shandler( 0 );

	//dummy return
	return 0;
}
