#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Server.h"
#include <iostream>
#include <cstdint>
#include <winsock2.h>
#include "stdint.h"
#pragma comment(lib, "Ws2_32.lib")
#include <WS2tcpip.h>
#include <string>
#include "UserDatabase.h"

#define MAX_BUFFER_SIZE 256

//initialize values
std::string prompt = "";
int port = 0;
int capacity = 1;
char commandChar = '~';
int currentClients = 0;
bool status = false;
bool sockets = false;
char buffer[MAX_BUFFER_SIZE];
UserDatabase hashTable;
std::vector<SOCKET> clientSockets;
Server server;
WSADATA wsaData;
fd_set readSet;
bool oneClient = false;

int main() {
	//WSA startup
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0) {
		std::cerr << "WSAStartup failed with error: " << result << std::endl;
		return 0;
	}

	//user prompt server setup
	server.input();

	//server info
	server.info();

	//server start
	server.init(port, capacity, commandChar);
	SOCKET serverSocket = server.getServerSocket();
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	//server status
	status = true;

	//server running
	while (status) {

		//clear readset
		FD_ZERO(&readSet);

		//adding client sockets to readset
		for (SOCKET clientSocket : clientSockets) {
			FD_SET(clientSocket, &readSet);
		}

		//server socket readset
		FD_SET(serverSocket, &readSet);

		//call select with timeout for multiple sockets
		int activity = select(serverSocket + 1, &readSet, NULL, NULL, &timeout);
		if (activity == SOCKET_ERROR) {
			std::cerr << "Select error, server shutdown\n";
			break;
		}

		//accept sockets with capacity max
		if (FD_ISSET(serverSocket, &readSet)) {
			SOCKET newSocket = accept(serverSocket, NULL, NULL);
			if (newSocket == INVALID_SOCKET) {
				std::cerr << "Failed to accept new connection\n";
			}
			else if (clientSockets.size() == capacity) {
				//rejection message if full
				std::string rejectionMessage = "Server capacity is full. You cannot join at the moment.";
				int bytesSent = server.sendMessage(newSocket, const_cast<char*>(rejectionMessage.c_str()), rejectionMessage.length());
				if (bytesSent != 0) {
					std::cerr << "Failed to send rejection message to the new client\n";
				}
				else {
					std::cout << "Sent rejection message to the new client\n";
				}
				closesocket(newSocket);
			}
			else {
				//add socket to group
				std::cout << "New client connected\n";
				clientSockets.push_back(newSocket);
				//welcome message
				std::string welcomeMessage = "Welcome to the server! Use ( " + std::string(1, commandChar) + " ) to execute commands.";
				int bytesSent = server.sendMessage(newSocket, const_cast<char*>(welcomeMessage.c_str()), welcomeMessage.length());
				if (bytesSent != 0) {
					std::cerr << "Failed to send connection message to the new client\n";
				}
				else {
					std::cout << "Sent connection message to the new client\n";
				}
			}
		}

		//check activity of sockets
		for (size_t i = 0; i < clientSockets.size(); ++i) {
			if (FD_ISSET(clientSockets[i], &readSet)) {
				//receive messages from sockets
				int bytesReceived = server.readMessage(clientSockets[i], buffer, MAX_BUFFER_SIZE);
				if (bytesReceived != 0) {
					//client disconnect, close socket
					std::cerr << "Client " << i << " disconnected\n";
					closesocket(clientSockets[i]);
					clientSockets.erase(clientSockets.begin() + i);
					--i;
				}
				else {
					std::cout << "Received message from client " << i << ": " << buffer << std::endl;
					std::string responseMessage = server.processMessage(buffer, bytesReceived);
					//command message or not
					if (buffer[0] == commandChar) {
						//send command response back to the same client
						int bytesSent = server.sendMessage(clientSockets[i], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
						if (bytesSent != 0) {
							std::cerr << "Failed to send command response to client " << i << "\n";
						}
						else {
							std::cout << "Sent command response to client " << i << ": " << responseMessage << std::endl;
						}
					}
					else {
						//regular message to all clients except sender
						for (size_t j = 0; j < clientSockets.size(); ++j) {
							if (i != j) {
								int bytesSent = server.sendMessage(clientSockets[j], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
								if (bytesSent != 0) {
									std::cerr << "Failed to send message to client " << j << "\n";
								}
								else {
									std::cout << "Relayed messages to client " << j << std::endl;
								}
							}
						}
					}
				}
			}
		}
	}

	//server stop
	server.stop();

	return 0;
}

void Server::info() {
	//get host name
	char hostname[256];
	gethostname(hostname, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	std::cout << "\nHostname: " << hostname << std::endl;

	//address info
	struct addrinfo* addressInfo = nullptr;
	struct addrinfo setup;
	memset(&setup, 0, sizeof(setup));
	setup.ai_family = AF_UNSPEC;
	setup.ai_socktype = SOCK_STREAM;
	setup.ai_protocol = IPPROTO_TCP;
	getaddrinfo(hostname, nullptr, &setup, &addressInfo);

	//print addresses
	std::cout << "\nAddress info: " << std::endl;
	int count = 0;
	void* addr;
	std::string iptype;
	for (struct addrinfo* ptr = addressInfo; ptr != nullptr; ptr = ptr->ai_next) {
		count++;
		//IPv4
		if (ptr->ai_family == AF_INET) {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
			addr = &(ipv4->sin_addr);
			iptype = "IPv4";
		}
		//IPv6
		else {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ptr->ai_addr;
			addr = &(ipv6->sin6_addr);
			iptype = "IPv6";
		}
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(ptr->ai_family, addr, ip, sizeof(ip));
		std::cout << "Address " << count << " (" << iptype << "): " << ip << std::endl;
	}
}

void Server::input() {
	std::cout << "Enter TCP port number\nInput: ";
	std::cin >> port;
	std::cout << "\nEnter Chat capacity (1-5)\nInput: ";
	std::cin >> capacity;
	std::cout << "\nEnter Command character Ex: '~'\nInput: ";
	std::cin >> commandChar;
}

int Server::init(uint16_t port, int capacity, char commandChar)
{
	//socket created
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET) {
		return SETUP_ERROR;
	}

	//setup address structure
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	serverAddr.sin_port = htons(port);

	//bind socket
	if (bind(getServerSocket(), (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		closesocket(getServerSocket());
		return BIND_ERROR;
	}

	//listener
	if (listen(getServerSocket(), capacity) == SOCKET_ERROR) {
		closesocket(getServerSocket());
		return SETUP_ERROR;
	}

	//set 1 socket active only
	if (capacity == 1) {
		oneClient = true;
	}

	return SUCCESS;
}

std::string Server::processMessage(const char* message, int length) {
	//check commands
	if (message[0] == commandChar && strncmp(message + 1, "help", 4) == 0) {
		std::string cmdChar(1, commandChar);
		return "Available commands:\n" + cmdChar + "help - Display available commands\n" + cmdChar + "register (username) (password) - Creates a registered account for the user\n";
	}
	else if (message[0] == commandChar && strncmp(message + 1, "shutdown66", 10) == 0) {
		//secret shutdown command
		status = false;
		return "Shutting down server! Order 66 executed.";
	}
	else if (message[0] == commandChar && strncmp(message + 1, "register", 8) == 0) {
		//split username and password
		std::string msg(message);
		size_t split1 = msg.find(' ', 9);
		size_t split2 = msg.find(' ', split1 + 1);
		if (split1 != std::string::npos && split2 != std::string::npos) {
			//store username and password
			std::string username = msg.substr(split1 + 1, split2 - split1 - 1);
			std::string password = msg.substr(split2 + 1);

			//username exist or not
			if ("" != hashTable.get(username)) {
				return "Username already exists, please choose a different name.";
			}
			//store user data in database
			hashTable.insert(username, password);

			//check database registered
			std::string storedPassword = hashTable.get(username);
			if (storedPassword == password) {
				return "Successfully registered user: " + username;
			}
			else {
				return "Failed to register user: " + username + " - Server Error";
			}
		}
		else {
			//invalid command format
			return "Invalid format for ~register command. Usage: ~register (username) (password)";
		}
	}
	else if (message[0] == commandChar && strncmp(message + 1, "login", 5) == 0) {
		//split username and password
		std::string msg(message);
		size_t split1 = msg.find(' ', 6);
		size_t split2 = msg.find(' ', split1 + 1);
		if (split1 != std::string::npos && split2 != std::string::npos) {
			//store username and password
			std::string username = msg.substr(split1 + 1, split2 - split1 - 1);
			std::string password = msg.substr(split2 + 1);

			//username exist or not
			if ("" == hashTable.get(username)) {
				return "Username does not exist, please register. Usage: ~register (username) (password)";
			}

			//check database registered
			std::string storedPassword = hashTable.get(username);
			if (storedPassword == password) {
				//login rules

				return "Successfully logged in user: " + username;
			}
			else {
				return "Failed to login user: " + username + " - Incorrect password.";
			}
		}
		else {
			//invalid command format
			return "Invalid format for ~register command. Usage: ~register (username) (password)";
		}
	}
	else {
		std::string input = message;
		return input;
	}
}

int Server::sendMessage(SOCKET clientSocket, char* data, int32_t length)
{
	uint8_t size = static_cast<uint8_t>(length + 1);
	int bytesSent = 0;
	int totalBytesSent = 0;

	//new buffer for sending and reset each time
	char sendBuffer[MAX_BUFFER_SIZE];
	memset(sendBuffer, 0, MAX_BUFFER_SIZE);
	memcpy(sendBuffer, &size, sizeof(size));
	memcpy(sendBuffer + sizeof(size), data, length + 1);

	//loop to ensure full data is being sent
	while (totalBytesSent < length + 1 + sizeof(size))
	{
		bytesSent = send(clientSocket, sendBuffer + totalBytesSent, length + 1 + sizeof(size) - totalBytesSent, 0);
		if (bytesSent == SOCKET_ERROR || bytesSent == 0)
		{
			return DISCONNECT;
		}
		totalBytesSent += bytesSent;
	}

	//ensure all bytes are sent
	if (totalBytesSent != length + 1 + sizeof(size))
	{
		return PARAMETER_ERROR;
	}

	return SUCCESS;
}

int Server::readMessage(SOCKET clientSocket, char* buffer, int32_t size)
{
	//clear buffer for new messages
	memset(buffer, 0, size);

	uint8_t length;
	int bytesReceived = recv(clientSocket, (char*)&length, sizeof(length), 0);
	if (bytesReceived <= 0)
	{
		if (bytesReceived == 0)
			return DISCONNECT;
		else
			return SHUTDOWN;
	}

	//loop to verify all data is being read
	int totalBytesReceived = 0;
	while (totalBytesReceived < length)
	{
		bytesReceived = recv(clientSocket, buffer + totalBytesReceived, length - totalBytesReceived, 0);
		if (bytesReceived <= 0)
		{
			if (bytesReceived == 0)
				return DISCONNECT;
			else
				return SHUTDOWN;
		}
		totalBytesReceived += bytesReceived;
	}

	//ensure all bytes are received
	if (totalBytesReceived != length)
	{
		return PARAMETER_ERROR;
	}

	return SUCCESS;
}

void Server::stop()
{
	if (clientSocket != INVALID_SOCKET) {
		shutdown(clientSocket, SD_BOTH);
		closesocket(clientSocket);
		clientSocket = INVALID_SOCKET;
	}
	if (serverSocket != INVALID_SOCKET) {
		closesocket(serverSocket);
		serverSocket = INVALID_SOCKET;
	}

	WSACleanup();
}
