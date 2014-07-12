Introduction
============

Q: What is libntoh?
A: Libntoh aims to be an user-friendly library to provide a easy way to perform defragmentation and reassembly of network/transport/(more?) protocols.

Q: Why libntoh?
A: It's true there are some libraries which aims to do the same things (like libnids), but libntoh is intended to provide a flexible, thread-safe and highly configurable environment for the final user. And most of all, libntoh is released under Modified BSD License to avoid many license issues.

Q: Which protocols does libntoh support?
A: Currently libntoh performs IPv4 defragmentation and TCP reassembly

Mailing List
============
There is a mailing list for libntoh development issues: libntoh-dev@safetybits.net

Getting the source
==================

$ git clone git://github.com/sch3m4/libntoh.git
Cloning into 'libntoh'...
remote: Reusing existing pack: 732, done.
remote: Counting objects: 33, done.
remote: Compressing objects: 100% (33/33), done.
remote: Total 765 (delta 12), reused 0 (delta 0)
Receiving objects: 100% (765/765), 1009.13 KiB | 416 KiB/s, done.
Resolving deltas: 100% (341/341), done.
$

Dependencies
============

To successfully compile libntoh you only need gcc, make, cmake, pkg-config and libpthread-dev.

Debian-like OS:

	$ sudo apt-get install cmake libpthread-dev gcc make build-essential pkg-config swig

If you want to generate the source code documentation, you will also need doxygen:

	$ sudo apt-get install doxygen

Note: pkg-config isn't really needed but it helps. (See "ntohexample" compilation)


You need CMake to compile libntoh and ntohexample.


Compilation instructions
========================

$ cd libntoh/src
../src$ mkdir build
../src$ cd build
../src/build$ cmake ..
-- The C compiler identification is GNU 4.7.2
-- The CXX compiler identification is GNU 4.7.2
-- Check for working C compiler: /usr/bin/gcc
-- Check for working C compiler: /usr/bin/gcc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Looking for include file pthread.h
-- Looking for include file pthread.h - found
-- Looking for pthread_create
-- Looking for pthread_create - not found.
-- Looking for pthread_create in pthreads
-- Looking for pthread_create in pthreads - not found
-- Looking for pthread_create in pthread
-- Looking for pthread_create in pthread - found
-- Found Threads: TRUE  
-- Found SWIG: /usr/bin/swig2.0 (found version "2.0.7") 
-- Found PythonLibs: /usr/lib/libpython2.7.so (found suitable version "2.7.3", required is "2.7") 
-- Configuring done
-- Generating done
-- Build files have been written to: /tmp/libntoh/src/build
../src/build$ make
[  8%] Swig source
Scanning dependencies of target _libntoh
[ 16%] Building C object CMakeFiles/_libntoh.dir/libntohPYTHON_wrap.c.o
/tmp/libntoh/src/build/libntohPYTHON_wrap.c: In function ‘init_libntoh’:
/tmp/libntoh/src/build/libntohPYTHON_wrap.c:10410:21: warning: variable ‘md’ set but not used [-Wunused-but-set-variable]
[ 25%] Building C object CMakeFiles/_libntoh.dir/libntoh.c.o
[ 33%] Building C object CMakeFiles/_libntoh.dir/tcpreassembly.c.o
[ 41%] Building C object CMakeFiles/_libntoh.dir/ipv4defrag.c.o
[ 50%] Building C object CMakeFiles/_libntoh.dir/common.c.o
[ 58%] Building C object CMakeFiles/_libntoh.dir/sfhash.c.o
Linking C shared module _libntoh.so
[ 58%] Built target _libntoh
Scanning dependencies of target ntoh
[ 66%] Building C object CMakeFiles/ntoh.dir/libntoh.c.o
[ 75%] Building C object CMakeFiles/ntoh.dir/tcpreassembly.c.o
[ 83%] Building C object CMakeFiles/ntoh.dir/ipv4defrag.c.o
[ 91%] Building C object CMakeFiles/ntoh.dir/common.c.o
[100%] Building C object CMakeFiles/ntoh.dir/sfhash.c.o
Linking C shared library libntoh.so
[100%] Built target ntoh
../src/build$ sudo make install
[sudo] password for sch3m4: 
[sudo] password for chema: 
[ 58%] Built target _libntoh
[100%] Built target ntoh
Install the project...
-- Install configuration: "Release"
-- Installing: /usr/local/lib/libntoh.so
-- Installing: /usr/local/include/libntoh/libntoh.h
-- Installing: /usr/local/include/libntoh/tcpreassembly.h
-- Installing: /usr/local/include/libntoh/sfhash.h
-- Installing: /usr/local/include/libntoh/ipv4defrag.h
-- Installing: /usr/local/include/libntoh/common.h
-- Installing: /usr/local/lib/pkgconfig/ntoh.pc
-- Installing: /usr/lib/python2.7/dist-packages/_libntoh.so
-- Installing: /usr/lib/python2.7/dist-packages/libntoh.py
../src/build$

For a more detailed description refer to
	https://github.com/sch3m4/libntoh/wiki	
	

Python Wrapper
==============

Once you have installed libntoh, you can use the python wrapper to comunicate with the library as follows:

~$ python
Python 2.7.3 (default, Mar 14 2014, 11:57:14) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from libntoh import ntoh_version
>>> print ntoh_version()
0.4a
>>> quit()
~$

A more complete example will be added soon.
	

"ntohexample" Compilation instructions
======================================

../libntoh$ cd example
../libntoh/example$ ./build.sh 
[i] pkg-config found: /usr/bin/pkg-config
[i] cmake found: /usr/bin/cmake
[i] make found: /usr/bin/make
[i] PKG_CONFIG_PATH set to: /usr/local/lib/pkgconfig
(...)
Linking C executable ntohexample
[100%] Built target ntohexample
../libntoh/example$

The default installation prefix is "/usr/local", so if you plan to link against libntoh using pkg-config
remember to add "/usr/local/lib/pkgconfig" to PKG_CONFIG_PATH:

$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
$ pkg-config --libs --cflags ntoh
-I/usr/local/include/libntoh  -L/usr/local/lib -lntoh

On the other hand you can change the installation prefix by defining CMAKE_INSTALL_PREFIX:

$ cmake ../ -DCMAKE_INSTALL_PREFIX=/usr

So the new installation prefix will be "/usr"

For more information, refer to the wiki page.


"ntohexample" Output:
=====================

$ sudo ./ntohexample 

###########################
#     libntoh Example     #
# ----------------------- #
# Written by Chema Garcia #
# ----------------------- #
#  http://safetybits.net  #
#   chema@safetybits.net  #
#   sch3m4@brutalsec.net  #
###########################

[i] libntoh version: 0.4a

[+] Usage: ./ntohexample <options>

+ Options:
	-i | --iface <val> -----> Interface to read packets from
	-f | --file <val> ------> File path to read packets from
	-F | --filter <val> ----> Capture filter (must contain "tcp" or "ip")
	-c | --client ----------> Receive client data only
	-s | --server ----------> Receive server data only

$ sudo ./ntohexample -i eth0 -F "tcp and host 10.0.0.1 and port 22"

###########################
#     libntoh Example     #
# ----------------------- #
# Written by Chema Garcia #
# ----------------------- #
#  http://safetybits.net  #
#   chema@safetybits.net  #
#   sch3m4@brutalsec.net  #
###########################

[i] libntoh version: 0.4a

[i] Source: eth0 / Ethernet
[i] Filter: tcp and host 10.0.0.1 and port 22
[i] Receive data from client: Yes
[i] Receive data from server: Yes
[i] Max. TCP streams allowed: 1024
[i] Max. IPv4 flows allowed: 1024


[SYN Sent] 10.0.0.2:40819 (SYN Sent | Window: 233600) ---> 10.0.0.1:22 (Listen | Window: 0)
	
[SYN Rcv] 10.0.0.1:22 (SYN Rcv | Window: 4194240) ---> 10.0.0.2:40819 (SYN Sent | Window: 233600)
	
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194240)
	
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 49 SEQ: 1 ACK: 1 Next SEQ: 50
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4193384)
	+ Data segment | Bytes: 32 SEQ: 1 ACK: 50 Next SEQ: 33
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 856 SEQ: 50 ACK: 33 Next SEQ: 906
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194240)
	+ Data segment | Bytes: 1272 SEQ: 33 ACK: 906 Next SEQ: 1305
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4193928)
	+ Data segment | Bytes: 80 SEQ: 1305 ACK: 906 Next SEQ: 1385
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 312 SEQ: 906 ACK: 1385 Next SEQ: 1218
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194240)
	+ Data segment | Bytes: 16 SEQ: 1385 ACK: 1218 Next SEQ: 1401
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194192)
	+ Data segment | Bytes: 48 SEQ: 1401 ACK: 1218 Next SEQ: 1449
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 48 SEQ: 1218 ACK: 1449 Next SEQ: 1266
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194176)
	+ Data segment | Bytes: 64 SEQ: 1449 ACK: 1266 Next SEQ: 1513
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 64 SEQ: 1266 ACK: 1513 Next SEQ: 1330
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4193920)
	+ Data segment | Bytes: 368 SEQ: 1513 ACK: 1330 Next SEQ: 1881
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 320 SEQ: 1330 ACK: 1881 Next SEQ: 1650
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194208)
	+ Data segment | Bytes: 640 SEQ: 1881 ACK: 1650 Next SEQ: 2521
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 32 SEQ: 1650 ACK: 2521 Next SEQ: 1682
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194192)
	+ Data segment | Bytes: 128 SEQ: 2521 ACK: 1682 Next SEQ: 2649
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233488)
	+ Data segment | Bytes: 48 SEQ: 1682 ACK: 2649 Next SEQ: 1730
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194160)
	+ Data segment | Bytes: 112 SEQ: 2649 ACK: 1730 Next SEQ: 2761
		
[Established] 10.0.0.1:22 (Established | Window: 4194208) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 80 SEQ: 1730 ACK: 2761 Next SEQ: 1810
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233600)
	+ Data segment | Bytes: 32 SEQ: 1810 ACK: 2761 Next SEQ: 1842
		
[Established] 10.0.0.1:22 (Established | Window: 4194240) ---> 10.0.0.2:40819 (Established | Window: 233568)
	+ Data segment | Bytes: 160 SEQ: 1842 ACK: 2761 Next SEQ: 2002
		
[Established] 10.0.0.2:40819 (Established | Window: 233536) ---> 10.0.0.1:22 (Established | Window: 4194240)
	+ Data segment | Bytes: 32 SEQ: 2761 ACK: 2002 Next SEQ: 2793
		
[Established] 10.0.0.2:40819 (Established | Window: 233600) ---> 10.0.0.1:22 (Established | Window: 4194240)
	+ Data segment | Bytes: 64 SEQ: 2793 ACK: 2002 Next SEQ: 2857
		
[Closing] 10.0.0.2:40819 (Fin Wait1 | Window: 233600) ---> 10.0.0.1:22 (Close Wait | Window: 4194240)
	
[Closing] 10.0.0.1:22 (Last ACK | Window: 4194240) ---> 10.0.0.2:40819 (Closing | Window: 233600)
	
[Closed] 10.0.0.2:40819 (Time Wait | Window: 233600) ---> 10.0.0.1:22 (Closed | Window: 4194240)

[+] Capture finished!
$
