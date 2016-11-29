/*
 * tcp.h
 *
 *  Created on: 2016-9-28
 *      Author: root
 */

#ifndef TCP_H_
#define TCP_H_

#include "pb.h"
#include "local_logger.h"

//#include <boost/asio.hpp>

//#include <bingo/tcp/all.h>
//using namespace bingo::tcp;

// ----------------------------- TCP_MESSAGE_PACKAGE ------------------------------ //
#pragma pack(1)
struct twsn_tcp_package{
	char data[1024];
};
#pragma pack()


// ----------------------------- PARSER ------------------------------ //
struct twsn_tcp_parser{
	static const size_t header_size;								// Parse size of package's header.
	static int max_wait_for_heartjump_seconds;						// If the value is 0, then server don't check heartjump.
	static int max_wait_for_authentication_pass_seconds;			// If the value is 0, then server don't check authentication pass.
};

// Make tcp acceptor entry.
void make_tcp_acceptor();

// Send data to client.
int send_tcp_package(void* hdr, const char* data, size_t data_size, error_what& ew);


#endif /* TCP_H_ */
