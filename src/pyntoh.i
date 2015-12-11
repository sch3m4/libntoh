%module pyntoh
%{
#define SWIG_FILE_WITH_INIT
#include <libntoh.h>
#include <ipv4defrag.h>
#include <ipv6defrag.h>
#include <tcpreassembly.h>
%}

%include <libntoh.h>
%include <ipv4defrag.h>
%include <ipv6defrag.h>
%include <tcpreassembly.h>

%typedef ntoh_ipv4_tuple4_t *pntoh_ipv4_tuple4_t;
%typedef ntoh_ipv4_flow_t *pntoh_ipv4_flow_t;

pntoh_ipv4_flow_t ntoh_ipv4_find_flow ( pntoh_ipv4_session_t ipsession, pntoh_ipv4_tuple4_t tuple );
pntoh_ipv4_flow_t ntoh_ipv4_new_flow ( pntoh_ipv4_session_t ipsession , pntoh_ipv4_tuple4_t tuple , PyObject *callback , void *udata , unsigned int *errno);
int ntoh_ipv4_add_fragment ( pntoh_ipv4_session_t session , pntoh_ipv4_flow_t flow , unsigned char *iphdr );
