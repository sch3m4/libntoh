![build status](https://travis-ci.org/sch3m4/libntoh.svg?branch=master)

### Introduction

**What is libntoh?**

Libntoh aims to be an user-friendly library to provide a easy way to perform defragmentation and reassembly of network/transport/(more?) protocols.


**Why libntoh?**

It's true there are some libraries which aims to do the same things (like libnids), but libntoh is intended to provide a flexible, thread-safe and highly configurable environment for the final user. And most of all, libntoh is released under Modified BSD License to avoid many license issues.


**Which protocols does libntoh support?**

Currently libntoh performs IPv4/IPv6 defragmentation and TCP reassembly over IPv4 and IPv6.

### Mailing List
There is a mailing list for libntoh development issues: libntoh-dev@safetybits.net

### Getting the source

	$ git clone git://github.com/sch3m4/libntoh.git
	Cloning into 'libntoh'...
	remote: Counting objects: 962, done.
	remote: Total 962 (delta 0), reused 0 (delta 0), pack-reused 962
	Receiving objects: 100% (962/962), 1.01 MiB | 121.00 KiB/s, done.
	Resolving deltas: 100% (483/483), done.
	Checking connectivity... hecho.
	$

### Dependencies

To successfully compile libntoh you only need gcc, make, cmake, pkg-config and libpthread-dev.

Debian-like OS:

	$ sudo apt-get install cmake libpthread-dev gcc make build-essential pkg-config

If you want to generate the source code documentation, you will also need doxygen:

	$ sudo apt-get install doxygen

Note: pkg-config isn't really needed but it helps. (See "ntohexample" compilation)


You need CMake to compile libntoh and ntohexample.


### Compilation instructions

	$ cd libntoh/src
	../src$ ./build.sh
	[i] pkg-config found: /usr/bin/pkg-config
	[i] cmake found: /usr/bin/cmake
	[i] make found: /usr/bin/make
	[i] PKG_CONFIG_PATH set to: /usr/local/lib/pkgconfig
	
	-- The C compiler identification is GNU 4.8.4
	-- The CXX compiler identification is GNU 4.8.4
	-- Check for working C compiler: /usr/bin/cc
	-- Check for working C compiler: /usr/bin/cc -- works
	-- Detecting C compiler ABI info
	-- Detecting C compiler ABI info - done
	-- Check for working CXX compiler: /usr/bin/c++
	-- Check for working CXX compiler: /usr/bin/c++ -- works
	-- Detecting CXX compiler ABI info
	-- Detecting CXX compiler ABI info - done
	-- Looking for include file pthread.h
	-- Looking for include file pthread.h - found
	-- Looking for pthread_create
	-- Looking for pthread_create - not found
	-- Looking for pthread_create in pthreads
	-- Looking for pthread_create in pthreads - not found
	-- Looking for pthread_create in pthread
	-- Looking for pthread_create in pthread - found
	-- Found Threads: TRUE  
	-- Configuring done
	-- Generating done
	-- Build files have been written to: /tmp/libntoh/src/build
	Scanning dependencies of target ntoh
	[ 16%] Building C object CMakeFiles/ntoh.dir/libntoh.c.o
	[ 33%] Building C object CMakeFiles/ntoh.dir/tcpreassembly.c.o
	[ 50%] Building C object CMakeFiles/ntoh.dir/ipv4defrag.c.o
	[ 66%] Building C object CMakeFiles/ntoh.dir/ipv6defrag.c.o
	[ 83%] Building C object CMakeFiles/ntoh.dir/common.c.o
	[100%] Building C object CMakeFiles/ntoh.dir/sfhash.c.o
	Linking C shared library libntoh.so
	[100%] Built target ntoh
	Do you want to perform the installation? [y/n]: y
	[sudo] password for chema: 
	[100%] Built target ntoh
	Install the project...
	-- Install configuration: "Release"
	-- Installing: /usr/local/lib/libntoh.so
	-- Installing: /usr/local/include/libntoh/libntoh.h
	-- Installing: /usr/local/include/libntoh/tcpreassembly.h
	-- Installing: /usr/local/include/libntoh/sfhash.h
	-- Installing: /usr/local/include/libntoh/ipv4defrag.h
	-- Installing: /usr/local/include/libntoh/ipv6defrag.h
	-- Installing: /usr/local/include/libntoh/common.h
	-- Installing: /usr/local/lib/pkgconfig/ntoh.pc
	$

For a more detailed description refer to
	https://github.com/sch3m4/libntoh/wiki	

### Libntoh Examples

You can find a working source code example for each supported protocol in "examples" folder:

	libntoh$ ls examples/ -R
	examples/:
	c
	
	examples/c:
	ipv4  ipv6  tcp_ipv4  tcp_ipv6
	
	examples/c/ipv4:
	build.sh  CMakeLists.txt  example.c
	
	examples/c/ipv6:
	build.sh  CMakeLists.txt  example.c
	
	examples/c/tcp_ipv4:
	build.sh  CMakeLists.txt  example.c
	
	examples/c/tcp_ipv6:
	build.sh  CMakeLists.txt  example.c


The default installation prefix for libntoh is "/usr/local", so if you plan to link against libntoh using pkg-config
remember to add "/usr/local/lib/pkgconfig" to PKG_CONFIG_PATH:

	$ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
	$ pkg-config --libs --cflags ntoh -I/usr/local/include/libntoh  -L/usr/local/lib -lntoh

On the other hand you can change the installation prefix by defining CMAKE_INSTALL_PREFIX:

	$ cmake ../ -DCMAKE_INSTALL_PREFIX=/usr

So the new installation prefix will be "/usr"

For more information, refer to the wiki page.

### "ntohexample" (TCP/IPv4) Output:

	$ sudo ./ntohexample 
	###########################
	#     libntoh Example     #
	# ----------------------- #
	# Written by Chema Garcia #
	# ----------------------- #
	#  http://safetybits.net  #
	#   chema@safetybits.net  #
	###########################
	
	[i] libntoh version: 0.4a
	
	[+] Usage: ./ntohexample <options>
	
	+ Options:
		  -i | --iface <val> -----> Interface to read packets from
		  -f | --file <val> ------> File path to read packets from
	 	  -F | --filter <val> ----> Capture filter (default: "ip and tcp")
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
