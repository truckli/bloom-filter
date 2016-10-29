all:
	gcc -o bloom_filter.o -c -I/home/truckli/Coding/wheels/Boost/boost_1_59_0 bloom_filter.c
	g++ -o hello.o -c -I/home/truckli/Coding/wheels/Boost/boost_1_59_0 hello.cpp
	g++ -o program hello.o bloom_filter.o -L/home/truckli/Coding/wheels/Boost/boost_1_59_0/stage/lib -lboost_system
	./program
