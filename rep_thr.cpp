/*
 * rep_thr.cpp
 *
 *  Created on: 2016-10-13
 *      Author: root
 */

#include "rep_thr.h"
#include "rb.h"
#include "tcp.h"
#include "local_logger.h"

#include <boost/crc.hpp>

#include <bingo/TCP/pack_and_unpack/net_layer.h>
using namespace bingo::TCP::pack_and_unpack;

// Unpack rabbitmq in stream.
void unpack_rabbitmq(char* header, net_layer*& net){
	size_t req_addr_size = 1 + RABBITMQ_ROUTINGEKEY_MAX_SIZE;
	char req_addr[req_addr_size];
	memset(req_addr, 0x00, req_addr_size);
	memcpy(req_addr, header + 1, RABBITMQ_ROUTINGEKEY_MAX_SIZE);

	u64_t session = 0;
	memcpy(&session, header + 1 + RABBITMQ_ROUTINGEKEY_MAX_SIZE, 8);

	net->req_addr = req_addr;
	net->session = session;
}

void top(twsn_rep_data_message*& msg, bingo_empty_type&){

	// Unpack message.
	TCP::pack_and_unpack::net_layer net;
	TCP::pack_and_unpack::net_layer* p_net = &net;

	char* p_msg = msg->data.header();

	// Unpack net-layer.
	unpack_rabbitmq(p_msg, p_net);

	size_t tcp_size = msg->data.length() - 1 - RABBITMQ_ROUTINGEKEY_MAX_SIZE - 8;
	char* tcp_header = msg->data.header() + 1 + RABBITMQ_ROUTINGEKEY_MAX_SIZE + 8;

	void* hdr = 0;
	memcpy(&hdr, &(net.session), 8);

	error_what er;
	if(send_tcp_package(hdr, tcp_header, tcp_size, er) == -1){
		string_ex t;
		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_TCP_RESPONSE_TASK,
				string_append().add("send tcp package fail! data:")
				->add(t.stream_to_string(msg->data.header(), msg->data.length()))->to_string()
				);
	}
}

void make_rep_task(){

	TCP_RESPONSE_TASK::construct(
				top					// thread_task queue top callback
				);
}

void free_rep_task(){
	TCP_RESPONSE_TASK::release();
}

