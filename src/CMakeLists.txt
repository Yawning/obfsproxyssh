include_directories("${PROJECT_SOURCE_DIR}/include")

#
# libevent 2.0.x
#

set(LIBEVENT_PATH /opt/libevent-2.0.21)
add_library(libevent STATIC IMPORTED)
set_target_properties(libevent
	PROPERTIES IMPORTED_LOCATION "${LIBEVENT_PATH}/lib/libevent_core.a"
)
include_directories("${LIBEVENT_PATH}/include")

#
# libssh2
#

set(LIBSSH2_PATH /opt/libssh2-1.4.3)
add_library(libssh2 STATIC IMPORTED)
set_target_properties(libssh2
	PROPERTIES IMPORTED_LOCATION "${LIBSSH2_PATH}/lib/libssh2.a"
)
include_directories("${LIBSSH2_PATH}/include")
find_package(OpenSSL)
find_package(ZLIB)


#
# This is my app, there are many others like it but this one is mine
#

set(obfsproxyssh_SRCS
	bstrlib.c
	libssh2_helpers.c
	obfsproxyssh_client.c
	tor_pt.c
	main.c
)

add_executable(obfsproxyssh ${obfsproxyssh_SRCS})
ADD_DEFINITIONS(-Wall -Werror)
target_link_libraries(obfsproxyssh libevent libssh2 ${CMAKE_THREAD_LIBS_INIT}
				${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})
