/********************************************************************************
 * Copyright (c) 2011, Chema Garcia                                             *
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
 * This example save the data sent by each peer in a separated file called: [src_ip]:[src_port]-[dst_ip]:[dst_port]
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

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <libntoh.h>

typedef struct
{
	unsigned char	*data;
	size_t		data_len;
	char		*path;
} peer_info_t , *ppeer_info_t;

#define RECV_CLIENT	1
#define RECV_SERVER	2

/* capture handle */
pcap_t 			*handle = 0;
pntoh_tcp_session_t	tcp_session = 0;
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
 * @brief Returns a struct which stores some peer information
 */
ppeer_info_t get_peer_info ( unsigned char *payload , size_t payload_len , pntoh_tcp_tuple5_t tuple )
{
	ppeer_info_t ret = 0;
	size_t len = 0;
	char path[1024] = {0};
        char            src[INET6_ADDRSTRLEN] = {0};
        char            dst[INET6_ADDRSTRLEN] = {0};

        inet_ntop ( AF_INET6 , (void*) &tuple->source , src , INET6_ADDRSTRLEN ); 
        inet_ntop ( AF_INET6 , (void*) &tuple->destination , dst , INET6_ADDRSTRLEN ); 

	/* gets peer information */
	ret = (ppeer_info_t) calloc ( 1 , sizeof ( peer_info_t ) );
	ret->data_len = payload_len;
	ret->data = (unsigned char*) calloc ( ret->data_len , sizeof ( unsigned char ) );
	memcpy ( ret->data , payload , ret->data_len );

	snprintf ( path , sizeof(path) , "%s:%d-" , src, ntohs(tuple->sport) );
	len = strlen(path);
	snprintf ( &path[len] , sizeof(path) - len, "%s:%d" , dst , ntohs(tuple->dport) );

	ret->path = strndup ( path , sizeof(path) );

	return ret;
}

/**
 * @brief Frees the ppeer_info_t struct
 */
void free_peer_info ( ppeer_info_t pinfo )
{
	/* free peer info data */
	if ( ! pinfo )
		return;

	free ( pinfo->data );
	free ( pinfo->path );
	free ( pinfo );

	return;
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
 * @brief Writes the ppeer_info_t data field to disk
 */
void write_data ( ppeer_info_t info )
{
	int fd = 0;

	if ( !info )
		return;

	if ( (fd = open ( info->path , O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW , S_IRWXU | S_IRWXG | S_IRWXO )) < 0 )
	{
		fprintf ( stderr , "\n[e] Error %d writting data to \"%s\": %s" , errno , info->path , strerror( errno ) );
		return;
	}

	write ( fd , info->data , info->data_len );
	close ( fd );

	return;
}

/**
 * @brief Send a TCP segment to libntoh
 */
void send_tcp_segment ( struct ip6_hdr *iphdr , pntoh_tcp_callback_t callback )
{
	ppeer_info_t		pinfo;
	ntoh_tcp_tuple5_t	tcpt5;
	pntoh_tcp_stream_t	stream;
	struct tcphdr 		*tcp;
	size_t 			size_ip;
	size_t			total_len;
	size_t			size_tcp;
	size_t			size_payload;
	unsigned char		*payload;
	int			ret;
	unsigned int		error;

	size_ip = sizeof ( struct ip6_hdr );
	total_len = size_ip + ntohs( iphdr->ip6_plen );

	tcp = (struct tcphdr*)((unsigned char*)iphdr + size_ip);
	if ( (size_tcp = tcp->th_off * 4) < sizeof(struct tcphdr) )
		return;

	payload = (unsigned char *)iphdr + size_ip + size_tcp;
	size_payload = total_len - (size_ip + size_tcp);

	ntoh_tcp_get_tuple5 ( (void*)iphdr , tcp , &tcpt5 );

	/* find the stream or creates a new one */
	if ( !( stream = ntoh_tcp_find_stream( tcp_session , &tcpt5 ) ) )
	{
		if ( ! ( stream = ntoh_tcp_new_stream( tcp_session , &tcpt5, callback , 0 , &error , 1 , 1 ) ) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new stream: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}

		fprintf ( stderr , "\nStream Creado!");
	}

	if ( size_payload > 0 )
		pinfo = get_peer_info ( payload , size_payload , &tcpt5 );
	else
		pinfo = 0;


	/* add this segment to the stream */
	switch ( ( ret = ntoh_tcp_add_segment( tcp_session , stream, (void*)iphdr, total_len, (void*)pinfo ) ) )
	{
		case NTOH_OK:
			break;

		case NTOH_SYNCHRONIZING:
			free_peer_info ( pinfo );
			break;

		default:
			fprintf( stderr, "\n[e] Error %d adding segment: %s", ret, ntoh_get_retval_desc( ret ) );
			free_peer_info ( pinfo );
			break;
	}

	return;
}

/**
 * @brief Sends a IPv6 fragment to libntoh
 */
void send_ipv6_fragment ( struct ip6_hdr *iphdr , pipv6_dfcallback_t callback )
{
	ntoh_ipv6_tuple4_t 	ipt4;
	pntoh_ipv6_flow_t 	flow;
	int 			ret;
	unsigned int		error;

	ntoh_ipv6_get_tuple4 ( iphdr , &ipt4 );

	if ( !( flow = ntoh_ipv6_find_flow( ipv6_session , &ipt4 ) ) )
		if ( ! (flow = ntoh_ipv6_new_flow( ipv6_session , &ipt4, callback, 0 , &error )) )
		{
			fprintf ( stderr , "\n[e] Error %d creating new IPv4 flow: %s" , error , ntoh_get_errdesc ( error ) );
			return;
		}

	if ( ( ret = ntoh_ipv6_add_fragment( ipv6_session , flow, iphdr ) ) )
		fprintf( stderr, "\n[e] Error %d adding IPv6: %s", ret, ntoh_get_retval_desc( ret ) );

	return;
}

/* TCP Callback */
void tcp_callback ( pntoh_tcp_stream_t stream , pntoh_tcp_peer_t orig , pntoh_tcp_peer_t dest , pntoh_tcp_segment_t seg , int reason , int extra )
{
        char            src[INET6_ADDRSTRLEN] = {0};
        char            dst[INET6_ADDRSTRLEN] = {0};

        inet_ntop ( AF_INET6 , (void*) &orig->addr , src , INET6_ADDRSTRLEN );
        inet_ntop ( AF_INET6 , (void*) &dest->addr , dst , INET6_ADDRSTRLEN );

	/* receive data only from the peer given by the user */
	if ( receive == RECV_CLIENT && stream->server.receive )
	{
		stream->server.receive = 0;
		return;
	}else if ( receive == RECV_SERVER && stream->client.receive )
	{
		stream->client.receive = 0;
		return;
	}

	fprintf ( stderr , "\n[%s] %s:%d (%s | Window: %lu) ---> " , ntoh_tcp_get_status ( stream->status ) , src , ntohs(orig->port) , ntoh_tcp_get_status ( orig->status ) , orig->totalwin );
	fprintf ( stderr , "%s:%d (%s | Window: %lu)\n\t" , dst , ntohs(dest->port) , ntoh_tcp_get_status ( dest->status ) , dest->totalwin );

	if ( seg != 0 )
		fprintf ( stderr , "SEQ: %lu ACK: %lu Next SEQ: %lu" , seg->seq , seg->ack , orig->next_seq );

	switch ( reason )
	{
		/* Data segment */
		case NTOH_REASON_DATA:
			fprintf ( stderr , " | Data segment | Bytes: %i" , seg->payload_len );

			/* write data */
			write_data( (ppeer_info_t) seg->user_data );

			if ( extra != 0 )
					fprintf ( stderr , " - %s" , ntoh_get_reason ( extra ) );

			break;

		default:
			switch ( extra )
			{
			    case NTOH_REASON_MAX_SYN_RETRIES_REACHED:
			    case NTOH_REASON_MAX_SYNACK_RETRIES_REACHED:
			    case NTOH_REASON_HSFAILED:
			    case NTOH_REASON_EXIT:
			    case NTOH_REASON_TIMEDOUT:
			    case NTOH_REASON_CLOSED:
				inet_ntop ( AF_INET6 , (void*) &stream->client.addr , src , INET6_ADDRSTRLEN );
				if ( extra == NTOH_REASON_CLOSED )
				    fprintf ( stderr , "\n\t+ Connection closed by %s (%s)" , stream->closedby == NTOH_CLOSEDBY_CLIENT ? "Client" : "Server" , src );
				else
				    fprintf ( stderr , "\n\t+ %s/%s - %s" , ntoh_get_reason ( reason ) , ntoh_get_reason ( extra ) , ntoh_tcp_get_status ( stream->status ) );

				break;

			    default:
				break;
			}

			break;
	}

	if ( seg != 0 )
		free_peer_info ( (ppeer_info_t) seg->user_data );

	fprintf ( stderr , "\n" );

	return;
}

/* IPv6 Callback */
void ipv6_callback ( pntoh_ipv6_flow_t flow , pntoh_ipv6_tuple4_t tuple , unsigned char *data , size_t len , unsigned short reason )
{
	unsigned int	i = 0;
        char            src[INET6_ADDRSTRLEN] = {0};
        char            dst[INET6_ADDRSTRLEN] = {0};

        inet_ntop ( AF_INET6 , (void*) &tuple->source , src , INET6_ADDRSTRLEN );
        inet_ntop ( AF_INET6 , (void*) &tuple->destination , dst , INET6_ADDRSTRLEN );

	fprintf( stderr, "\n\n[i] Got an IPv4 datagram! (%s - %d) %s --> ", ntoh_get_reason(reason) , reason , src );
	fprintf( stderr, "%s | %zu/%zu bytes - Key: %04x - ID: %02x - Proto: %d (%s)\n\n", dst , len, flow->total , flow->key, ntohs( tuple->id ), tuple->protocol, get_proto_description( tuple->protocol ) );

	if ( tuple->protocol == IPPROTO_TCP )
		send_tcp_segment ( (struct ip6_hdr*) data , &tcp_callback );
	else
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
	char 			errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program 	fp;
	char 			filter_exp[] = "ip6 and tcp";
	char 			*source = 0;
	char 			*filter = filter_exp;
	const unsigned char	*packet = 0;
	struct pcap_pkthdr 	header;

	/* packet dissection */
	struct ip6_hdr	*ip;
	unsigned int	error;

	/* extra */
	unsigned int ipf,tcps;

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
		fprintf( stderr, "\n\t-F | --filter <val> ----> Capture filter (default: \"ip6 and tcp\")" );
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

	ntoh_init ();

	if ( ! (tcp_session = ntoh_tcp_new_session ( 0 , 0 , &error ) ) )
	{
		fprintf ( stderr , "\n[e] Error %d creating TCP session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -5 );
	}

	fprintf ( stderr , "\n[i] Max. TCP streams allowed: %d" , ntoh_tcp_get_size ( tcp_session ) );

	if ( ! (ipv6_session = ntoh_ipv6_new_session ( 0 , 0 , &error )) )
	{
		ntoh_tcp_free_session ( tcp_session );
		fprintf ( stderr , "\n[e] Error %d creating IPv4 session: %s" , error , ntoh_get_errdesc ( error ) );
		exit ( -6 );
	}

	fprintf ( stderr , "\n[i] Max. IPv6 flows allowed: %d\n\n" , ntoh_ipv6_get_size ( ipv6_session ) );

	/* capture starts */
	while ( ( packet = pcap_next( handle, &header ) ) != 0 )
	{
		/* get packet headers */
		ip = (struct ip6_hdr*) ( packet + sizeof ( struct ether_header ) );

		/* it is an IPv4 fragment */
		if ( NTOH_IPV6_IS_FRAGMENT(ip) )
			send_ipv6_fragment ( ip , &ipv6_callback );
		/* or a TCP segment */
		else if ( ip->ip6_nxt == IPPROTO_TCP )
			send_tcp_segment ( ip , &tcp_callback );
	}

	tcps = ntoh_tcp_count_streams( tcp_session );
	ipf = ntoh_ipv6_count_flows ( ipv6_session );

	/* no streams left */
	if ( ipf + tcps > 0 )
	{
		fprintf( stderr, "\n\n[+] There are currently %i stored TCP stream(s) and %i IPv6 flow(s). You can wait them to get closed or press CTRL+C\n" , tcps , ipf );
		pause();
	}

	shandler( 0 );

	//dummy return
	return 0;
}
