CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 FATAL_ERROR )
PROJECT ( LIBNTOH )

# set project version
SET ( ${PROJECT_NAME}_MAJOR_VERSION "0" )
SET ( ${PROJECT_NAME}_MINOR_VERSION "5" )
SET ( ${PROJECT_NAME}_STATUS_VERSION "b" )
SET ( ${PROJECT_NAME}_VERSION "${${PROJECT_NAME}_MAJOR_VERSION}.${${PROJECT_NAME}_MINOR_VERSION}${${PROJECT_NAME}_STATUS_VERSION}" )
# set project include dir.
SET ( LIBNTOH_INC inc )
SET ( CMAKE_INCLUDE_PATH "/usr/include" )
# set build type
SET ( CMAKE_BUILD_TYPE Release )
# set sources
SET ( LIBNTOH_SRCS libntoh.c tcpreassembly.c ipv4defrag.c ipv6defrag.c common.c sfhash.c )
# set cflags
SET ( CMAKE_C_FLAGS "-Wall -Os -O3 -pipe -fPIC" )
#SET ( CMAKE_C_FLAGS "-g -Wall -Os -O3 -pipe" ) // static: comment the line above and uncomment this one to compile as static library (contrib by Di3)
# set output name
SET ( OUTPUT_LIB ntoh )
# set interface files
SET ( MODULE_NAME libntoh )
#SET ( INTERFACE_FILES libntoh.i tcpreassembly.i common.i sfhash.i ipv4defrag.i )

SET_SOURCE_FILES_PROPERTIES ( ${INTERFACE_FILES} PROPERTIES CPLUSCPLUS OFF )


# required libraries
FIND_PACKAGE ( Threads REQUIRED )

# set include directories
INCLUDE_DIRECTORIES ( ${LIBNTOH_INC} )
INCLUDE_DIRECTORIES ( ${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES ( ${CMAKE_INCLUDE_PATH})

# set target from source
ADD_LIBRARY( ${OUTPUT_LIB} SHARED ${LIBNTOH_SRCS} )
ADD_LIBRARY( ${OUTPUT_LIB}_static STATIC ${LIBNTOH_SRCS} )
SET_PROPERTY(TARGET ${OUTPUT_LIB} PROPERTY POSITION_INDEPENDENT_CODE 1)
SET_PROPERTY(TARGET ${OUTPUT_LIB}_static PROPERTY POSITION_INDEPENDENT_CODE 1)

# pkgconfig file
CONFIGURE_FILE ( ntoh.pc.in ntoh.pc @ONLY )

# link against required libraries
TARGET_LINK_LIBRARIES( ${OUTPUT_LIB} ${CMAKE_THREAD_LIBS_INIT})

###########################
# set install information #
###########################
# library
INSTALL ( TARGETS ${OUTPUT_LIB} LIBRARY DESTINATION lib )
INSTALL ( TARGETS ${OUTPUT_LIB}_static ARCHIVE DESTINATION lib )
# headers
INSTALL ( FILES ${LIBNTOH_INC}/libntoh.h ${LIBNTOH_INC}/tcpreassembly.h ${LIBNTOH_INC}/sfhash.h ${LIBNTOH_INC}/ipv4defrag.h ${LIBNTOH_INC}/ipv6defrag.h ${LIBNTOH_INC}/common.h DESTINATION include/libntoh )
# pkconfig file
INSTALL ( FILES ${CMAKE_CURRENT_BINARY_DIR}/ntoh.pc DESTINATION lib/pkgconfig)
# swig

