/*
 * tcp.cpp
 *
 *  Created on: 2016-9-28
 *      Author: root
 */

#include "tcp.h"

#include "rev_thr.h"

#include <bingo/TCP/config/receiver_cfg.h>
#include <bingo/TCP/tcp_svr_handler.h>
#include <bingo/TCP/tcp_svr_hdr_manager.h>
#include <bingo/TCP/tcp_server.h>
using namespace bingo::TCP;

const size_t twsn_tcp_parser::header_size = 2;
#ifdef MY_TEST
int twsn_tcp_parser::max_wait_for_heartjump_seconds = 0;
int twsn_tcp_parser::max_wait_for_authentication_pass_seconds = 0;
#else
int twsn_tcp_parser::max_wait_for_heartjump_seconds = 20;
int twsn_tcp_parser::max_wait_for_authentication_pass_seconds = 10;
#endif

char heartbeat_package_header[2] = {0xaa, 0x08};
char heartbeat_package_const[4] = {0xaa, 0x55, 0xaa, 0x55};
char request_system_time_package_validate[3] = {0x6a, 0x0a, 0x11};
char identify_package_header[2] = {0xaa, 0x0b};
char identify_package_const[4] = {0x1b, 0x11, 0x12, 0x7f};
char identify_package_mac[24][6] = {
		{0x00, 0x00, 0xb4, 0x00, 0x22, 0xee},
		{0x00, 0x00, 0xb4, 0x00, 0x32, 0x5e},
		{0x00, 0x48, 0x54, 0x8a, 0xf0, 0xca},
		{0x00, 0x48, 0x54, 0x8a, 0xf0, 0xc9},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0x59},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0xe6},
		{0x00, 0x48, 0x54, 0x8a, 0xf3, 0xc7},
		{0x00, 0x80, 0xc8, 0x43, 0x59, 0xba},
		{0x00, 0x80, 0xc8, 0x43, 0x59, 0xbe},
		{0x00, 0x00, 0xb4, 0x00, 0x22, 0xe3},
		{0x00, 0x00, 0xb4, 0x00, 0x32, 0x3e},
		{0x00, 0x48, 0x54, 0x8a, 0xf0, 0xc1},
		{0x00, 0x48, 0x54, 0x8a, 0xf0, 0xc3},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0x50},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0xe7},
		{0x00, 0x48, 0x54, 0x8a, 0xf3, 0xc4},
		{0x00, 0x00, 0xb4, 0x00, 0x23, 0xee},
		{0x00, 0x00, 0xb4, 0x00, 0x33, 0x5e},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0xca},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0xc9},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0x5a},
		{0x00, 0x48, 0x54, 0x8a, 0xf1, 0xed},
		{0x00, 0x48, 0x54, 0x8a, 0xf3, 0xc8},
		{0x00, 0x80, 0xc8, 0x43, 0x59, 0xbc}};


// ----------------------------- SOCKET_MANAGER ------------------------------ //
class twsn_tcp_handler;
typedef bingo::singleton_v0<tcp_svr_hdr_manager<twsn_tcp_handler> > twsn_tcp_mgr;

// ----------------------------- HANDLER ------------------------------ //

class twsn_tcp_handler : public tcp_svr_handler<twsn_tcp_parser, twsn_tcp_package>{
public:
	twsn_tcp_handler(boost::asio::io_service& io_service) :
		tcp_svr_handler<twsn_tcp_parser,twsn_tcp_package>(io_service){

	}

	int read_pk_header_complete_func(
			twsn_tcp_handler::pointer p,
				char*& rev_data,
				size_t& rev_data_size,
				size_t& remain_size,
				error_what& e_what){

//		if(memcmp(rev_data, identify_package_header, 2) == 0){
//			// Identify frame
//			remain_size = 12;
//		}else if(memcmp(rev_data, heartbeat_package_header, 2) == 0){
//			// Heartbeat frame
//			remain_size = 9;
//		}else{
//			// Data frame
//			u16_t size = 0;
//			memcpy(&size, rev_data + 1, 1);
//			remain_size = size + 1;
//		}

		// Data frame
		u16_t size = 0;
		memcpy(&size, rev_data + 1, 1);
		remain_size = size + 1;

		{
			string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
					(string_append().add("hdr:")
					->add(t.pointer_to_long((void*)p.get()))
					->add(",read_pk_header_complete, data:")
					->add(t.stream_to_string(rev_data, rev_data_size))
					->add(",remain_size:")
					->add(remain_size)
					->to_string()));
		}

		return 0;
	}

	int read_pk_full_complete_func(
			twsn_tcp_handler::pointer p,
				char*& rev_data,
				size_t& rev_data_size,
				error_what& e_what){

		{
			string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
					(string_append().add("hdr:")
					->add(t.pointer_to_long((void*)p.get()))
					->add(",read_pk_full_complete, data:")
					->add(t.stream_to_string(rev_data, rev_data_size))
					->to_string()));
		}

		// Whether is identify frame.
		if(memcmp(rev_data, identify_package_header, 2) == 0){
			return validate_identify_frame(rev_data, rev_data_size, e_what) ;
		}

		// Whether is request system time.
		if(memcmp(rev_data, request_system_time_package_validate, 1) == 0 &&
				memcmp(rev_data + 1, request_system_time_package_validate + 1, 1) ==0 &&
				memcmp(rev_data + 6, request_system_time_package_validate + 2, 1) == 0){
			return validate_request_system_time(rev_data, rev_data_size, e_what);
		}

		// Whether is heartbeat.
		if(memcmp(rev_data, heartbeat_package_header, 2) == 0 &&
			memcmp(rev_data + 2, heartbeat_package_const, 4) == 0){
			return validate_heartbeat(rev_data, rev_data_size, e_what) ;
		}

		// Close socket before the socket is authentication.
		if(!this->is_authentication_pass_){
			e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
			e_what.err_message("common package has no authentication!");
			return -1;
		}

		// Check header.
		{
			char chrCmp1 = 0x6a;
			char chrCmp2 = 0x6c;
			if(memcmp(rev_data, &chrCmp1, 1) != 0 && memcmp(rev_data, &chrCmp2, 1) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("common package header is error!");
				return -1;
			}
		}

		// Check length.
		{
			if(rev_data_size < 4){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("common package validate length fail!");
				return -1;
			}
		}

		// Check crc.
		{
			u8_t chr = rev_data[1] ^ rev_data[2];
			for (int i = 3; i < rev_data_size - 1; i++) {
				chr = chr ^ rev_data[i];
			}
			if(memcmp(&chr, rev_data + rev_data_size -1, 1) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("common package validate crc fail!");
				return -1;
			}
		}

		{
			bingo::string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
								string_append().add("hdr:")
								->add(t.pointer_to_long((void*)p.get()))
								->add(", receive common package success")
								->add(",data:")
								->add(t.stream_to_string(rev_data, rev_data_size))
								->to_string());
			return 0;
		}

		// Make new data, new data = hdr(8 byte) + rev_data_size;
		size_t n_data_size = 8 + rev_data_size;
		char n_data[n_data_size];
		memset(&n_data, 0x00, n_data_size);

		// Get hdr.
		twsn_tcp_handler* hdr = this;
		memcpy(n_data, &hdr, 8);

		// Get rev_data
		memcpy(n_data+8, rev_data, rev_data_size);

		// Push message to rev_task.
		twsn_rev_data_message* msg = new twsn_rev_data_message();

		// Copy stream to sart_rev_data_message.
		if(msg->data.copy(n_data, n_data_size, e_what) == -1){
			bingo::string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_TCP_ACCEPTOR,
					string_append().add("hdr:")
					->add(t.pointer_to_long((void*)p.get()))
					->add(", copy stream to twsn_rev_data_message fail, err_code:")
					->add(e_what.err_no())
					->add(", err_msg:")
					->add(string(e_what.err_message()))
					->add(",data:")
					->add(t.stream_to_string(rev_data, rev_data_size))
					->to_string());
			delete msg;

			return 0;
		}

		if(TCP_RECEIVER_TASK::instance()->put(msg, e_what) == -1){			// Input T into queue

			bingo::string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_TCP_ACCEPTOR,
						(string_append().add("hdr:")
						->add(t.pointer_to_long((void*)p.get()))
						->add(", put message to rev_task fail, err_code:")
						->add(e_what.err_no())
						->add(", err_msg:")
						->add(string(e_what.err_message()))
						->add(",data:")
						->add(t.stream_to_string(rev_data, rev_data_size))
						->to_string()));
			delete msg;

		}else{

			bingo::string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
					(string_append().add("hdr:")
					->add(t.pointer_to_long((void*)p.get()))
					->add(", put message to rev_task success, data:")
					->add(t.stream_to_string(rev_data, rev_data_size))
					->to_string()));
		}

		return 0;
	}

	int active_send_in_ioservice_func(
			twsn_tcp_handler::pointer p,
			package*& pk,
			error_what& e_what){

//		char* snd_p = pk->header();
//		if(snd_p[1] == 0x01){
//			// authencation is pass
//			p->set_authentication_pass();
//			cout << "hdr:" << p.get() << ",do set_authentication_pass()" << endl;
//		}

		return 0;
	}

	void catch_error_func(twsn_tcp_handler::pointer p, error_what& e_what){
		string_ex t;
		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_TCP_ACCEPTOR,
				(string_append().add("hdr:")
				->add(t.pointer_to_long((void*)p.get()))
				->add(",err_code:")
				->add(e_what.err_no())
				->add(",err_msg:")
				->add(e_what.err_message().c_str())
				->add(",do catch_error()")
				->to_string()));
	}

	void close_complete_func(twsn_tcp_handler::pointer p, int& ec_value){
		error_what e_what;
		if(twsn_tcp_mgr::instance()->erase(p.get(), e_what) == 0){
			string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
						(string_append().add("hdr:")
						->add(t.pointer_to_long((void*)p.get()))
						->add(",do close_completed_erase_hander_mgr(),success")
						->to_string()));
		}else{
			string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_TCP_ACCEPTOR,
						(string_append().add("hdr:")
						->add(t.pointer_to_long((void*)p.get()))
						->add(",do close_completed_erase_hander_mgr(),ec_value:")
						->add(ec_value)
						->to_string()));
		}
	}

	void write_pk_full_complete_func(
				pointer p,
				char*& snd_p,
				size_t& snd_size,
				const boost::system::error_code& ec){
		if(!ec){
			string_ex t;
			LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
					(string_append().add("hdr:")
					->add(t.pointer_to_long((void*)p.get()))
					->add(",write data success, data:")
					->add(t.stream_to_string(snd_p, snd_size))
					->to_string()));
		}
	}

private:
	int validate_identify_frame(char*& rev_data, size_t& rev_data_size, error_what& e_what){
		// Validate const
		{
			if(memcmp(rev_data + 2, identify_package_const, 4) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("identify package const is mismatching!");
				return -1;
			}
		}

		// Validate mac-address.
		{
			bool is_mac_succ = false;
			for (int i = 0; i < 24; i++) {
				if(memcmp(rev_data + 2 + 4, &identify_package_mac[i][0], 6) ==0){
					is_mac_succ = true;
					break;
				}
			}
			if(!is_mac_succ){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("identify package mac-address is mismatching!");
				return -1;
			}
		}

		// Validate crc.
		{
			u8_t chr = rev_data[0] ^ rev_data[1];
			for (int i = 2; i < rev_data_size - 1; i++) {
				chr = chr ^ rev_data[i];
			}
			if(memcmp(rev_data + rev_data_size - 1, &chr, 1) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("identify package crc is mismatching!");
				return -1;
			}
		}

		// Make response package.
		{
			char rep[13] = {0x55, 0x0a,
					0x1b, 0x11, 0x12, 0xdd, 0xd3, 0x7f, 0x00, 0x2a, 0x14, 0x00,
					0x0f};

			// Make validate code.
			u16_t code = 0;
			memcpy(&code, rev_data + rev_data_size - 2, 2);
			u32_t cal = 5762 * code;
			char cal_p[4];
			memset(cal_p, 0x00, 4);
			memcpy(cal_p, &cal, 4);

			memcpy(rep + 9, cal_p, 1);
			memcpy(rep + 6, cal_p + 1, 1);
			memcpy(rep + 5, cal_p + 2, 1);
			memcpy(rep + 10, cal_p + 3, 1);

			// Make crc
			u8_t chr = rep[0] ^ rep[1];
			for (int i = 2; i < 12; i++) {
				chr = chr ^ rev_data[i];
			}
			rep[12] = chr;

			// Make package.
			package* pk = new package();
			if(pk->copy(rep, 13, e_what) == -1){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				return -1;
			}
			boost::asio::async_write(socket_,
									buffer(pk->header(), pk->length()),
									boost::bind(&twsn_tcp_handler::write_handler,
											this->shared_from_this(),
											boost::asio::placeholders::error,
											boost::asio::placeholders::bytes_transferred,
											pk));
		}

		// Authentication is pass.
		set_authentication_pass();

		return 0;
	}

	int validate_request_system_time(char*& rev_data, size_t& rev_data_size, error_what& e_what){
		// Validate crc.
		{
			u8_t chr = rev_data[1] ^ rev_data[2];
			for (int i = 3; i < rev_data_size - 1; i++) {
				chr = chr ^ rev_data[i];
			}
			if(memcmp(rev_data + rev_data_size - 1, &chr, 1) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("request system time package crc is mismatching!");
				return -1;
			}
		}

		// Get now.
		ptime p1 = boost::posix_time::microsec_clock::local_time();
		int year = p1.date().year() - 2000;
		int month = p1.date().month();
		int day = p1.date().day();

		int week_of_day = p1.date().day_of_week();
		if(week_of_day == 0)
			week_of_day = 7; // Sunday
		int week_of_month = day / 7;
		if((week_of_day - (day % 7)) < 0)
			week_of_month++;

		int hour = p1.time_of_day().hours();
		int minute = p1.time_of_day().minutes();
		int second = p1.time_of_day().seconds();

		// Make response package.
		{
			char rep[19] = {0x66, 0x10,
					0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
			memcpy(rep + 2, rev_data + 2, 4);
			rep[7] = rev_data[7];
			memcpy(rep + 8, rev_data + 8, 4);

			memcpy(rep + 12, &second, 1);
			memcpy(rep + 13, &minute, 1);
			memcpy(rep + 14, &hour, 1);
			memcpy(rep + 15, &day, 1);

			u8_t cweek = 0x00;
			memcpy(&cweek, &week_of_month, 1);
			u8_t cmonth = 0x00;
			memcpy(&cmonth, &month, 1);
			cmonth = cmonth << 4;
			cmonth += cweek;
			memcpy(rep + 16, &cmonth, 1);

			memcpy(rep + 17, &year, 1);

			// Make crc
			u8_t chr = rep[1] ^ rep[2];
			for (int i = 3; i < 18; i++) {
				chr = chr ^ rep[i];
			}
			rep[18] = chr;

			// Make package.
			package* pk = new package();
			if(pk->copy(rep, 19, e_what) == -1){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				return -1;
			}
			boost::asio::async_write(socket_,
									buffer(pk->header(), pk->length()),
									boost::bind(&twsn_tcp_handler::write_handler,
											this->shared_from_this(),
											boost::asio::placeholders::error,
											boost::asio::placeholders::bytes_transferred,
											pk));
		}

		return 0;
	}

	int validate_heartbeat(char*& rev_data, size_t& rev_data_size, error_what& e_what){
		// Validate crc.
		{
			u8_t chr = rev_data[0] ^ rev_data[1];
			for (int i = 2; i < rev_data_size - 1; i++) {
				chr = chr ^ rev_data[i];
			}
			if(memcmp(rev_data + rev_data_size - 1, &chr, 1) != 0){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				e_what.err_message("heartbeat package crc is mismatching!");
				return -1;
			}
		}

		// Make response package.
		{
			char rep[11] = {0x55, 0x08,
								0x55, 0xaa, 0x55, 0xaa, 0x00, 0x00, 0x00, 0x00,
								0x00};
			memcpy(rep + 6, rev_data + 6, 4);

			// Make crc
			u8_t chr = rep[0] ^ rep[1];
			for (int i = 2; i < 10; i++) {
				chr = chr ^ rev_data[i];
			}
			rep[10] = chr;

			// Make package.
			package* pk = new package();
			if(pk->copy(rep, 11, e_what) == -1){
				e_what.err_no(ERROR_TYPE_TCP_PACKAGE_BODY_IS_ERROR);
				return -1;
			}
			boost::asio::async_write(socket_,
									buffer(pk->header(), pk->length()),
									boost::bind(&twsn_tcp_handler::write_handler,
											this->shared_from_this(),
											boost::asio::placeholders::error,
											boost::asio::placeholders::bytes_transferred,
											pk));
		}

		// Update heartbeat p1_.
		set_heartjump_datetime();

		return 0;
	}
};

// ----------------------------- SERVER ------------------------------ //

class sart_tcp_server : public tcp_server<twsn_tcp_handler, twsn_tcp_mgr, twsn_tcp_parser>{
public:
	sart_tcp_server(boost::asio::io_service& io_service, string& ipv4, u16_t& port):
		tcp_server<twsn_tcp_handler, twsn_tcp_mgr, twsn_tcp_parser>(io_service, ipv4, port){

	}

	int accept_success_func(sart_tcp_server::pointer ptr, error_what& e_what){

		twsn_tcp_mgr::instance()->push(ptr.get());

		string_ex t;
		LOCAL_LOG_VISITOR_TYPE::instance()->handle(LOG_LEVEL_DEBUG, LOG_TAG_TCP_ACCEPTOR,
					(string_append().add("hdr:")
					->add(t.pointer_to_long((void*)ptr.get()))
					->add(",do accept_success_func() success")
					->to_string()));

		return 0;
	}
};

// ----------------------------- make_tcp_acceptor --------------------------------- //
void make_tcp_acceptor(){

	bingo::TCP::config::tcp_receiver_cfg  config;
	if(!config.read_xml()){

		CONSOLE_LOGGER_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_MAIN_FUNCTION,
				string_append().add("read tcp configuration fail, err_msg:")
				->add(config.err().err_message().c_str())->to_string()
				);

		// Close progresss.
		exit(0);
		return;
	}

	twsn_tcp_mgr::construct();	 			// Create tcp_handler_manager.

	try{
		 boost::asio::io_service io_service;
		 string ipv4 = config.get_cfg().ip;
		 u16_t port =config.get_cfg().port;
		 sart_tcp_server server(io_service, ipv4, port);

		 io_service.run();

	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	CONSOLE_LOGGER_TYPE::instance()->handle(LOG_LEVEL_ERROR, LOG_TAG_MAIN_FUNCTION,
					string_append().add("tcp ios exist!")->to_string()
					);

	twsn_tcp_mgr::release();
}

int send_tcp_package(void* hdr, const char* data, size_t data_size, error_what& ew){
	return twsn_tcp_mgr::instance()->send_data(hdr, data, data_size, ew);
}
