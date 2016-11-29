/*
 * local_logger.h
 *
 *  Created on: 2016-9-27
 *      Author: root
 */

#ifndef LOCAL_LOGGER_H_
#define LOCAL_LOGGER_H_

#include "pb.h"

class local_logger : public log::log_handler{
public:
	local_logger();
	virtual ~local_logger();

	void handle(int level, const char* tag, std::string& info);
};

typedef bingo::singleton_v0<local_logger> CONSOLE_LOGGER_TYPE;

#endif /* LOCAL_LOGGER_H_ */
