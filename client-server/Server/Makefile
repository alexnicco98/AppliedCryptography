all:server.cpp
	g++ server.cpp -lpthread -I ./../ -L/usr/local/lib -o server.o -lssl -lcrypto
	./server.o 8080