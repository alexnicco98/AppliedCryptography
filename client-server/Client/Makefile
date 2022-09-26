all:client.cpp
	g++ client.cpp -lpthread -I ./../ -L/usr/local/lib -o client.o -lssl -lcrypto
	./client.o localhost bob 8080