%module pyntoh
%{
#include <libntoh.h>
#include <common.h>
#include <ipv4defrag.h>
#include <ipv6defrag.h>
#include <sfhash.h>
#include <tcpreassembly.h>
%}

%include <libntoh.h>
%include <common.h>
%include <ipv4defrag.h>
%include <ipv6defrag.h>
%include <sfhash.h>
%include <tcpreassembly.h>
