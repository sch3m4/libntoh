CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 FATAL_ERROR )
PROJECT ( LIBNTOH )

# set source files and flags
SET ( LIBNTOH_SRCS libntoh.c tcpreassembly.c ipv4defrag.c )
SET ( CMAKE_CXX_FLAGS "-Wall -Os -O2 -ansi -pedantic -pipe" )
SET ( LIBNTOH_INC inc )

# set project version
SET ( ${PROJECT_NAME}_MAJOR_VERSION "0" )
SET ( ${PROJECT_NAME}_MINOR_VERSION "3" )
SET ( ${PROJECT_NAME}_STATUS_VERSION "a" )
SET ( ${PROJECT_NAME}_VERSION "${${PROJECT_NAME}_MAJOR_VERSION}.${${PROJECT_NAME}_MINOR_VERSION}${${PROJECT_NAME}_STATUS_VERSION}" )

# set include directories
INCLUDE_DIRECTORIES ( ${LIBNTOH_INC} )

SET ( CMAKE_BUILD_TYPE Release )

# set output library name
SET ( OUTPUT_LIB ntoh )

# set target from source
ADD_LIBRARY( ${OUTPUT_LIB} SHARED ${LIBNTOH_SRCS} )

# pkgconfig file
CONFIGURE_FILE ( ntoh.pc.in ntoh.pc @ONLY )

# link against required libraries
FIND_PACKAGE ( Threads REQUIRED )
TARGET_LINK_LIBRARIES( ${OUTPUT_LIB} ${CMAKE_THREAD_LIBS_INIT})

###########################
# set install information #
###########################
# library
INSTALL ( TARGETS ${OUTPUT_LIB} LIBRARY DESTINATION lib )
# headers
INSTALL ( FILES ${LIBNTOH_INC}/libntoh.h ${LIBNTOH_INC}/tcpreassembly.h ${LIBNTOH_INC}/ipv4defrag.h ${LIBNTOH_INC}/uthash.h DESTINATION include/libntoh )
# pkconfig file
INSTALL ( FILES ${CMAKE_CURRENT_BINARY_DIR}/ntoh.pc DESTINATION lib/pkgconfig)