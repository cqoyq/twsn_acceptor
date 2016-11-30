INCLUDE = -I$(BOOST_INCLUDE_ROOT) \
          -I$(BINGO_INCLUDE_ROOT_v3)
          
ifeq ($(ConfigName),Debug)
LIBS = -lpthread \
	   -lrt \
	   -lbingo_v3_d \
	   -lboost_random \
	   -lboost_regex \
       -lboost_chrono \
	   -lboost_timer \
	   -lboost_system \
	   -lboost_thread \
	   -lboost_context \
	   -lboost_coroutine \
       -lboost_unit_test_framework
else
 LIBS = -lpthread \
	   -lrt \
	   -lbingo_v3 \	   
	   -lboost_random \
	   -lboost_regex \
       -lboost_chrono \
	   -lboost_timer \
	   -lboost_system \
	   -lboost_thread \
	   -lboost_context \
	   -lboost_coroutine \
       -lboost_unit_test_framework
endif
	  
LIBPATH = -L$(BOOST_LIB_ROOT) \
		   -L$(MY_LIB_ROOT_v3)

OBJS =  main.o \
			local_logger.o \
			rb.o \
			pb.o \
			tcp.o \
			rev_thr.o \
			rep_thr.o
		
ifeq ($(ShowDebug),y)
DEBUGS = -DMY_DEBUG
else
DEBUGS =
endif

ifeq ($(ConfigName),Debug)
CXXFLAGS =	-O2 -g -Wall -fmessage-length=0 -std=c++11 $(DEBUGS)  $(INCLUDE)
else
CXXFLAGS =	-O2 -Wall -fmessage-length=0  -std=c++11 $(INCLUDE)
endif

TARGET = twsn_acceptor

$(TARGET):	$(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LIBS) $(LIBPATH);
	cp $(TARGET) $(MY_LIB_ROOT_v3)/service/twsn_acceptor

all: $(TARGET)

debug: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)


