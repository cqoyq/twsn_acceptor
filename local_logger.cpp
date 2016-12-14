/*
 * locallogger.cpp
 *
 *  Created on: 2016-9-27
 *      Author: root
 */

#include "local_logger.h"

#include <boost/date_time/posix_time/posix_time.hpp>
using namespace boost::posix_time;

//string get_now(){
//	string now;
//	ptime p1 = boost::posix_time::microsec_clock::local_time();
//	int year = p1.date().year();
//	int month = p1.date().month();
//	int day = p1.date().day();
//
//	int hour = p1.time_of_day().hours();
//	int minute = p1.time_of_day().minutes();
//	int second = p1.time_of_day().seconds();
//
//	int millsecond = p1.time_of_day().total_milliseconds() - p1.time_of_day().total_seconds()*1000;
//
//	char ctime[25];
//	memset(&ctime[0], 0x00, 25);
//
//	sprintf(&ctime[0], "%4d-%02d-%02d %02d:%02d:%02d.%03d", year, month, day, hour, minute, second, millsecond);
//	now.append(ctime);
//
//	return now;
//}

local_logger::local_logger() : log_factory() {
	// TODO Auto-generated constructor stub

}

local_logger::~local_logger() {
	// TODO Auto-generated destructor stub
}

//void local_logger::handle(int level, const char* tag, std::string& info){
//	cout << get_now() << "@" << tag << "@" <<  level_to_string((log_level)level) << "@" << info << endl;
//}

