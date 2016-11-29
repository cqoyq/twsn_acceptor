/*
 * main.cpp
 *
 *  Created on: 2016-9-27
 *      Author: root
 */

#include "rb.h"
#include "tcp.h"
#include "rev_thr.h"
#include "rep_thr.h"

void init(){

	RABBITMQ_FACTORY_TYPE::construct();		// Rabbitmq client and server.

	CONSOLE_LOGGER_TYPE::construct();		// Logger to console.
	LOCAL_LOG_VISITOR_TYPE::construct();		// Logger to rabbitmq-server.
	if(!LOCAL_LOG_VISITOR_TYPE::instance()->make_rabbitmq_logger(RABBITMQ_FACTORY_TYPE::instance())){
		cout << "make local logger fail! error:" << LOCAL_LOG_VISITOR_TYPE::instance()->err().err_message() << endl;
		exit(0);
	}

	make_rev_task();
	make_rep_task();
}

void destory(){
	RABBITMQ_FACTORY_TYPE::release();

	CONSOLE_LOGGER_TYPE::release();
	LOCAL_LOG_VISITOR_TYPE::release();

	free_rev_task();
	free_rep_task();
}

int main (int argc, char *argv[]) {

	// Init-func
	init();

	boost::thread t1(make_rb_sendor);
	boost::thread t2(make_rb_receiver);
	boost::thread t3(make_tcp_acceptor);

	t1.join();
	t2.join();
	t3.join();

	// Free memory.
	destory();

	return 0;
}


