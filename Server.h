#pragma once

#include <cstdint>
#include <winsock2.h> 
#include <iostream>

class Server
{
public:
	SOCKET getServerSocket() const { return serverSocket; }

	void input();
	void info();
	int init(uint16_t port, int capacity, char commandChar);
	std::string processMessage(SOCKET clientSocket, const char* message, int length);
	int readMessage(SOCKET clientSocket, char* buffer, int32_t size);
	int sendMessage(SOCKET clientSocket, char* data, int32_t length);
	void stop();

private:
	SOCKET serverSocket;
	SOCKET clientSocket;

	const uint8_t SUCCESS = 0, SHUTDOWN = 1, DISCONNECT = 2,
		BIND_ERROR = 3, CONNECT_ERROR = 4, SETUP_ERROR = 5,
		STARTUP_ERROR = 6, ADDRESS_ERROR = 7, PARAMETER_ERROR = 8, MESSAGE_ERROR = 9;
};