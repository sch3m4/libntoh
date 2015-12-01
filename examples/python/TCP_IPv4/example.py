import pyntoh
import binascii
from struct import *
from scapy.all import *

PCAP_FILE='/tmp/ip_frag_source.pcap'

# ip header flags
FLAGS_MF = 1
FLAGS_DF = 2

def ipv4_callback ( flow , iptuple , data , dlen , reason ):
	return

def send_ip_fragment ( header , callback ):
	ipt4 = None
	pyntoh.ntoh_ipv4_get_tuple4 ( header , ipt4 )
	print repr(ipt4)
	return

def main():
	pyntoh.ntoh_init()
	errnum = None

	tcp_session = pyntoh.ntoh_tcp_new_session ( 0 , 0 , errnum )
	if tcp_session is None:
		print "[%d] Error creating TCP session: %s" % (errnum , pyntoh.ntoh_get_errdesc(errnum) )
		return

	print "[i] Max. TCP flows allowed: %d" % pyntoh.ntoh_tcp_get_size ( tcp_session )

	ipv4_session = pyntoh.ntoh_ipv4_new_session ( 0 , 0 , errnum )
	if ipv4_session is None:
		print "[%d] Error creating IPv4 session: %s" % (errnum , pyntoh.ntoh_get_errdesc(errnum) )
		pyntoh.ntoh_tcp_free_session(tcp_session)
		return

	print "[i] Max. IPv4 flows allowed: %d" % pyntoh.ntoh_ipv4_get_size ( ipv4_session )

	pkts = rdpcap ( PCAP_FILE )
	for pkt in pkts:
		if pkt[IP].flags == FLAGS_MF:
			send_ip_fragment ( str(pkt)[:(pkt[IP].ihl * 4)] , ipv4_callback )
#		s_addr = socket.inet_ntoa(iph[8]);
#		d_addr = socket.inet_ntoa(iph[9]);
#		print "Off: %s - %s => %s" % ( binascii.unhexlify(str(iph[2]) ), str(s_addr) , str(d_addr) )

		print ""











if __name__ == "__main__":
	main()
