/*
 * rb.h
 *
 *  Created on: 2016-9-27
 *      Author: root
 */

#ifndef RB_H_
#define RB_H_

#include "pb.h"
#include "local_logger.h"

#include <bingo/RabbitMQ/rabbitmq_factory.h>
using namespace bingo::RabbitMQ;

typedef bingo::singleton_v0<rabbitmq_factory> RABBITMQ_FACTORY_TYPE;

// ------------------------------- rabbitmq-sendor -------------------------------------- //

void make_rb_sendor();

// ------------------------------- rabbitmq-receiver -------------------------------------- //

void make_rb_receiver();


#endif /* RB_H_ */
