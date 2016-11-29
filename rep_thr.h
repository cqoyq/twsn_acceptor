/*
 * rep_thr.h
 *
 *  Created on: 2016-10-13
 *      Author: root
 */

#ifndef REP_THR_H_
#define REP_THR_H_

#include "pb.h"
#include "local_logger.h"

// --------------------------- message ------------------------- //

#pragma pack(1)
struct twsn_rep_package{
	char message[TCP_MESSAGE_MAX_SIZE];
};
#pragma pack()

typedef bingo::thread::task_message_data<twsn_rep_package> 	twsn_rep_data_message;
typedef bingo::thread::task_exit_data				   							twsn_rep_exit_message;

// --------------------------- many_to_one ------------------------- //

typedef bingo::thread::many_to_one<
		twsn_rep_data_message,
		twsn_rep_exit_message
	> twsn_rep_task;
typedef bingo::singleton_v1<twsn_rep_task, twsn_rep_task::thr_top_callback> TCP_RESPONSE_TASK;

void make_rep_task();
void free_rep_task();

#endif /* REP_THR_H_ */
