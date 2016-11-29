/*
 * rev_thr.h
 *
 *  Created on: 2016-9-28
 *      Author: root
 */

#ifndef REV_THR_H_
#define REV_THR_H_

#include "pb.h"
#include "local_logger.h"

// --------------------------- message ------------------------- //

#pragma pack(1)
struct twsn_rev_package{
	char message[RABBITMQ_MESSAGE_MAX_SIZE];
};
#pragma pack()

typedef bingo::thread::task_message_data<twsn_rev_package> 	twsn_rev_data_message;
typedef bingo::thread::task_exit_data				   							twsn_rev_exit_message;

// --------------------------- many_to_one ------------------------- //

typedef bingo::thread::many_to_one<
		twsn_rev_data_message,
		twsn_rev_exit_message
	> twsn_rev_task;
typedef bingo::singleton_v1<twsn_rev_task, twsn_rev_task::thr_top_callback> TCP_RECEIVER_TASK;

void make_rev_task();
void free_rev_task();

#endif /* REV_THR_H_ */
