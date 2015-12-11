#!/usr/bin/env python
#

import binascii
import socket
import codecs
from pyntoh import *
from struct import *
from scapy.all import *

PCAP_FILE='/tmp/ip_frag_source.pcap'

ipv4_session = None
tcp_session = None
errnum = None

# ip header flags
FLAGS_MF = 1
FLAGS_DF = 2

def ipv4_callback ( flow , iptuple , data , dlen , reason ):
	print ("en callback")
	return

#	if ( !( flow = ntoh_ipv4_find_flow( ipv4_session , &ipt4 ) ) )
#		if ( ! (flow = ntoh_ipv4_new_flow( ipv4_session , &ipt4, callback, 0 , &error )) )
#		{
#			fprintf ( stderr , "\n[e] Error %d creating new IPv4 flow: %s" , error , ntoh_get_errdesc ( error ) );
#			return;
#		}
#
#	if ( ( ret = ntoh_ipv4_add_fragment( ipv4_session , flow, iphdr ) ) )
#		fprintf( stderr, "\n[e] Error %d adding IPv4: %s", ret, ntoh_get_retval_desc( ret ) );



def send_ip_fragment ( header , callback ):
	global errnum
	global ipv4_session

	tuple4 = ntoh_ipv4_tuple4_t()
	params = unpack('!2B3H2BH2I',bytes(header)[:20])

	tuple4.source = params[8]
	tuple4.destination = params[9]
	tuple4.id = params[3]
	tuple4.protocol = params[6]

	flow = ntoh_ipv4_find_flow ( ipv4_session , tuple4 )
	if flow is None:
		print ("flujo no encontrado")
		flow = ntoh_ipv4_new_flow ( ipv4_session , tuple4 , ipv4_callback , None , errnum )
		if flow is None:
			print ("Error al crear")
		else:
			print ("Flujo creado!")
	else:
		print ("flujo encontrado!")

	print ("Agregando fragmento...")
#	print ( binascii.hexlify ( bytes ( header ) ) )
	header = b'1122334455667788990011223344556677889900'
	val = ntoh_ipv4_add_fragment ( ipv4_session , flow , str(header ) )
	if val != NTOH_OK:
		print ("Error %d: %s" % ( val, ntoh_get_retval_desc ( val ) ) )
	else:
		print ("Fragmento agregado!")

	print ("\n")

	return

def main():
	global ipv4_session
	global tcp_session
	global errnum

	ntoh_init()

	tcp_session = ntoh_tcp_new_session ( 0 , 0 , errnum )
	if tcp_session is None:
		print ( "[%d] Error creating TCP session: %s" % (errnum , ntoh_get_errdesc(errnum) ) )
		return

	print ( "[i] Max. TCP flows allowed: %d" % ntoh_tcp_get_size ( tcp_session ) )

	ipv4_session = ntoh_ipv4_new_session ( 0 , 0 , errnum )
	if ipv4_session is None:
		print ( "[%d] Error creating IPv4 session: %s" % (errnum , ntoh_get_errdesc(errnum) ) )
		ntoh_tcp_free_session(tcp_session)
		return

	print ( "[i] Max. IPv4 flows allowed: %d" % ntoh_ipv4_get_size ( ipv4_session ) )

	pkts = rdpcap ( PCAP_FILE )
	for pkt in pkts:
		if pkt[IP].flags == FLAGS_MF:
			iphdr = bytes ( pkt[IP])
			send_ip_fragment ( pkt[IP] , ipv4_callback )
			print ( "\n" )

	ntoh_ipv4_free_session ( ipv4_session )
	ntoh_ipv4_exit()
	ntoh_exit()










if __name__ == "__main__":
	main()
