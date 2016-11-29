/*
 * rb.cpp
 *
 *  Created on: 2016-9-28
 *      Author: root
 */
#include "rb.h"

#include "rep_thr.h"

// ------------------------------- rabbitmq-sendor -------------------------------------- //

void make_rb_sendor(){
	// Create rabbitmq-logger.
	LOCAL_LOG_VISITOR_TYPE::instance()->make_rabbitmq_logger(RABBITMQ_FACTORY_TYPE::instance());

	log_handler* p = CONSOLE_LOGGER_TYPE::instance();
	// Create rabbitmq-sendor.
	if(!RABBITMQ_FACTORY_TYPE::instance()->make_p2p_sendor(p)){
		string_append ap;
		ap.add("make sendor fail!, err_msg:")->add(RABBITMQ_FACTORY_TYPE::instance()->err().err_message().c_str());
		p->handle(LOG_LEVEL_ERROR, LOG_TAG_RABBITMQ_SENDOR, ap.to_string());

		// Close progresss.
		exit(0);

	}else{
		string_append ap;
		ap.add("make sendor success!");
		p->handle(LOG_LEVEL_DEBUG, LOG_TAG_RABBITMQ_SENDOR, ap.to_string());
	}
}

// ------------------------------- rabbitmq-receiver -------------------------------------- //

void rev(string& msg){

	// Push message to rep_task.
	error_what e_what;
	twsn_rep_data_message* data = new twsn_rep_data_message();

	// Copy stream to twsn_rep_data_message.
	if(data->data.copy(msg.c_str(), msg.length(), e_what) == -1){
		string_ex t;
		string_append ap;
		ap.add("copy stream to rep_task fail, err_code:")
									->add(e_what.err_no())
									->add(", err_msg:")
									->add(string(e_what.err_message()))
									->add(",data:")
									->add(t.stream_to_string(msg.c_str(), msg.length()));

		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_RABBITMQ_RECEIVER, ap.to_string());
		delete data;

		return;
	}

	if(TCP_RESPONSE_TASK::instance()->put(data, e_what) == -1){			// Input T into queue

		string_ex t;
		string_append ap;
		ap.add("put message to rep_task fail, err_code:")
									->add(e_what.err_no())
									->add(", err_msg:")
									->add(string(e_what.err_message()))
									->add(",data:")
									->add(t.stream_to_string(msg.c_str(), msg.length()));

		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_RABBITMQ_RECEIVER, ap.to_string());
		delete data;

	}else{

		string_ex t;
		string_append ap;
		ap.add("put message to rep_task success, data:")
									->add(t.stream_to_string(msg.c_str(), msg.length()));
		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_RABBITMQ_RECEIVER, ap.to_string());
	}
}

void make_rb_receiver(){

	log_handler* p = CONSOLE_LOGGER_TYPE::instance();
	if(!RABBITMQ_FACTORY_TYPE::instance()->make_p2p_receiver(p, bind(rev, _1))){

		string_append ap;
		ap.add("make receiver fail!, err:")
												->add(string(RABBITMQ_FACTORY_TYPE::instance()->err().err_message()));
		p->handle(LOG_LEVEL_ERROR, LOG_TAG_RABBITMQ_RECEIVER, ap.to_string());
		// Close progresss.
		exit(0);

	}else{

		string_append ap;
		ap.add("make receiver succee!");
		p->handle(LOG_LEVEL_DEBUG, LOG_TAG_RABBITMQ_RECEIVER, ap.to_string());

	}
}

