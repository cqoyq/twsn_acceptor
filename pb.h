/*
 * pb.h
 *
 *  Created on: 2016-9-27
 *      Author: root
 */

#ifndef PB_H_
#define PB_H_

#include <boost/crc.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
using namespace boost;

#include <bingo/type.h>
#include <bingo/singleton.h>
#include <bingo/string.h>
#include <bingo/config/node.h>
#include <bingo/log/log_handler.h>
#include <bingo/log/log_level.h>
#include <bingo/log/log_factory.h>
#include <bingo/thread/all.h>
using namespace bingo;
using namespace bingo::log;

#define LOG_TAG_MAIN_FUNCTION			"twsn_acceptor_main"
#define LOG_TAG_RABBITMQ_SENDOR 	"twsn_acceptor_rabbitmq_sendor"
#define LOG_TAG_RABBITMQ_RECEIVER 	"twsn_acceptor_rabbitmq_receiver"
#define LOG_TAG_TCP_ACCEPTOR 			"twsn_acceptor_tcp_service"
#define LOG_TAG_TCP_REV_TASK				"twsn_acceptor_rev_task"
#define LOG_TAG_TCP_RESPONSE_TASK	"twsn_acceptor_response_task"

typedef bingo::singleton_v0<log::log_factory> LOCAL_LOG_VISITOR_TYPE;

#define RABBITMQ_ROUTINGEKEY_MAX_SIZE  50
#define RABBITMQ_LOCAL_SERVER_ROUTINGEKEY  			"twsn_acceptor_service"
#define RABBITMQ_KEY_TYPE_INFO_SERVICE 					"info_service"

#define TCP_MESSAGE_MAX_SIZE 				1024
#define RABBITMQ_MESSAGE_MAX_SIZE 		2048

#endif /* PB_H_ */
