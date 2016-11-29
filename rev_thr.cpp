/*
 * revthr.cpp
 *
 *  Created on: 2016-9-28
 *      Author: root
 */

#include "rev_thr.h"
#include "rb.h"

// Transfer rabbitmq data.
void transfer_data(char* data, size_t data_size){
	string key = RABBITMQ_KEY_TYPE_INFO_SERVICE;
	RABBITMQ_FACTORY_TYPE::instance()->transfer_data_by_key(key, data, data_size);
}

void top(twsn_rev_data_message*& msg, bingo_empty_type&){

	string source_routingkey = RABBITMQ_LOCAL_SERVER_ROUTINGEKEY;

	// Make new stream.
	size_t data_size = 1 + RABBITMQ_ROUTINGEKEY_MAX_SIZE + msg->data.length();
	char data[data_size];
	memset(data, 0x00, data_size);
	data[0] = 0x01;
	memcpy(data + 1, source_routingkey.c_str(), source_routingkey.length());
	memcpy(data + 1 + RABBITMQ_ROUTINGEKEY_MAX_SIZE,  msg->data.header(), msg->data.length());

	// Send data to MQ.
	char* p = data;
	transfer_data(p, data_size);
}

void make_rev_task(){

	TCP_RECEIVER_TASK::construct(
				top					// thread_task queue top callback
				);
}

void free_rev_task(){
	TCP_RECEIVER_TASK::release();
}

