#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define BUFFER_OVERFLOW -1
#include "Server.h"
#include <iostream>
#include <cstdint>
#include <winsock2.h>
#include "stdint.h"
#pragma comment(lib, "Ws2_32.lib")
#include <WS2tcpip.h>
#include <string>
#include "UserDatabase.h"
#include <list>
#include <unordered_map>
#include <cstring>
#include "LogDatabase.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <thread>
#include <chrono>

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
std::unordered_map<SOCKET, std::string> usernames;
Server server;
WSADATA wsaData;
fd_set readSet;
bool oneClient = false;
std::string logouter = "loggingout";
LogDatabase logDB("LogFiles/commands.log", "LogFiles/messages.log");

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

	//broadcast starts
	std::thread broadcastThread(broadcastThreadFunc);

	//record start in logs
	logDB.logCommand("\n--Server start--");

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
			else if (clientSockets.size() >= capacity + 10) {
				//rejection message if server full, set +10 buffer for users to attempt register for if/when chat capacity opens up and maximize socket allowance.
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
				std::string welcomeMessage = "Welcome to the server! Use (" + std::string(1, commandChar) + "help) to get started.";
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
					//client disconnect, logout if needed
					auto it = std::find_if(usernames.begin(), usernames.end(),
						[&](const auto& entry) { return entry.second == usernames[clientSockets[i]]; });
					if (it != usernames.end()) {
						//remove name from list
						std::cout << "Successfully logged out user: " + usernames[clientSockets[i]] << std::endl;
						usernames.erase(it);
					}
					//close socket
					std::cerr << "Client " << i << " disconnected\n";
					closesocket(clientSockets[i]);
					clientSockets.erase(clientSockets.begin() + i);
					--i;
				}
				else {
					std::cout << "Received message from client " << i << ": " << buffer << std::endl;
					std::string responseMessage = server.processMessage(clientSockets[i], buffer, bytesReceived);
					//command message or not
					if (buffer[0] == commandChar) {
						//send command response back to the same client
						logDB.logCommand(buffer); //input user command log
						int bytesSent = server.sendMessage(clientSockets[i], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
						if (bytesSent != 0) {
							std::cerr << "Failed to send message to client " << i << "\n";
							if (bytesSent == -1) {
								responseMessage = "Message is too long!";
								int bytesSent = server.sendMessage(clientSockets[i], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
								std::cerr << "Message length was too long" << "\n";
							}
						}
						else {
							std::cout << "Sent command response to client " << i << ": " << responseMessage << std::endl;
							logDB.logCommand(responseMessage); //output user command log
							if (logouter == responseMessage) {
								//client disconnect, close socket
								std::cerr << "Client " << i << " disconnected\n";
								closesocket(clientSockets[i]);
								clientSockets.erase(clientSockets.begin() + i);
								--i;
							}
						}
					}
					else {
						//dont allow unless logged in
						if (usernames.find(clientSockets[i]) != usernames.end()) {
							//regular message to all clients except sender and unregistered users
							logDB.logMessage(buffer); //public message log
							for (size_t j = 0; j < clientSockets.size(); ++j) {
								if (i != j) {
									if (usernames.find(clientSockets[j]) != usernames.end()) {
										int bytesSent = server.sendMessage(clientSockets[j], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
										if (bytesSent != 0) {
											std::cerr << "Failed to send message to client " << j << "\n";
											if (bytesSent == -1) {
												responseMessage = "Message is too long!";
												int bytesSent = server.sendMessage(clientSockets[j], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
												std::cerr << "Message length was too long" << "\n";
											}
										}
										else {
											std::cout << "Relayed messages to client " << j << std::endl;
										}
									}
								}
							}
						}
						else {
							//send command response back to the same client for no login
							logDB.logCommand(responseMessage); //output user command log
							int bytesSent = server.sendMessage(clientSockets[i], const_cast<char*>(responseMessage.c_str()), responseMessage.length());
							if (bytesSent != 0) {
								std::cerr << "Failed to send command response to client " << i << "\n";
							}
							else {
								std::cout << "Sent command response to client " << i << ": " << responseMessage << std::endl;
							}
						}
					}
				}
			}
		}
	}

	//server stop
	broadcastThread.join();
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

	//set username count to socket count
	//usernames.resize(capacity);

	return SUCCESS;
}

std::string Server::processMessage(SOCKET clientSocket, const char* message, int length) {
	//check commands
	std::string cmdChar(1, commandChar);
	//non login based commands
	if (message[0] == commandChar && strncmp(message + 1, "help", 4) == 0) {
		std::string helpLine;
		if (strncmp(message + 1, "help 1", 6) == 0) {
			//help page 1
			helpLine = "Help Page 1/2:\n";
			helpLine += cmdChar + "register (username) (password) - Creates a registered account for the user\n";
			helpLine += cmdChar + "login (username) (password) - Logs user into the chat\n";
			helpLine += cmdChar + "logout (username) - Logs user out of chat and disconnects from server\n";
		}
		else if (strncmp(message + 1, "help 2", 6) == 0) {
			//help page 2
			helpLine = "Help Page 2/2:\n";
			helpLine += cmdChar + "getlist - Retrieves a list of currently logged in users\n";
			helpLine += cmdChar + "getlog - Retrieves a log of previously sent public messages\n";
			helpLine += cmdChar + "send (username) (message) - Send a private message to the user\n";
		}
		else if (strlen(message) == 5) {
			//help page 1 default with no page
			helpLine = "Help Page 1/2:\n";
			helpLine += cmdChar + "register (username) (password) - Creates a registered account for the user\n";
			helpLine += cmdChar + "login (username) (password) - Logs user into the chat\n";
			helpLine += cmdChar + "logout (username) - Logs user out of chat and disconnects from server\n";
		}
		else {
			//invalid command format
			return "Invalid format for help command. Usage: " + cmdChar + "help (1) or (2)";
		}
		return helpLine;
	}
	else if (message[0] == commandChar && strncmp(message + 1, "register", 8) == 0) {
		//split username and password
		std::string msg(message);
		size_t split1 = msg.find(' ', 9);
		size_t split2 = msg.find(' ', split1 + 1);
		if (split1 != std::string::npos && split2 != std::string::npos) {
			//reject registration if registration capacity is full
			if (hashTable.getSize() >= capacity) {
				std::string rejectionMessage = "Server capacity is full. You cannot join at the moment.";
				return rejectionMessage;
			}
			//accept registration
			else {
				//store username and password
				std::string username = msg.substr(split1 + 1, split2 - split1 - 1);
				std::string password = msg.substr(split2 + 1);

				//username exist or not
				if ("" != hashTable.get(username)) {
					return "Username already exists, please choose a different name or login with existing account. Usage: " + cmdChar + "login (username) (password)";
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
		}
		else {
			//invalid command format
			return "Invalid format for register command. Usage: " + cmdChar + "register (username) (password)";
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
				return "Username does not exist, please register. Usage: " + cmdChar + "register (username) (password)";
			}

			//user already logged in or trying to login to another account
			if (usernames.find(clientSocket) != usernames.end()) {
				std::string loggedInUsername = usernames[clientSocket];
				if (loggedInUsername == username) {
					return "You are already logged in";
				}
				else {
					return "You can not login to another account while logged in";
				}
			}

			//user is already logged in from another client
			for (const auto& user : usernames) {
				if (user.second == username) {
					return "User is already logged in from another client";
				}
			}

			//check database registered
			std::string storedPassword = hashTable.get(username);
			if (storedPassword == password) {
				usernames[clientSocket] = username;
				return "Successfully logged in user: " + username;
			}
			else {
				return "Failed to login user: " + username + " - Incorrect password";
			}
		}
		else {
			//invalid command format
			return "Invalid format for login command. Usage: " + cmdChar + "login (username) (password)";
		}
	}
	else if (message[0] == commandChar && strncmp(message + 1, "getlist", 7) == 0) {
		std::string clientNames = "";
		for (const auto& entry : usernames) {
			clientNames += entry.second + "\n";
		}
		if (clientNames.empty()) {
			return "No users logged in";
		}
		return "List of Active Clients:\n" + clientNames;
	}

	//dont allow unless logged in
	if (usernames.find(clientSocket) != usernames.end()) {
		if (message[0] == commandChar && strncmp(message + 1, "shutdown66", 10) == 0) {
			//secret shutdown command
			status = false;
			return "Shutting down server! Order 66 executed.";
		}
		else if (message[0] == commandChar && strncmp(message + 1, "send", 4) == 0) {
			//split username and message
			std::string msg(message);
			size_t split1 = msg.find(' ', 5);
			size_t split2 = msg.find(' ', split1 + 1);
			std::string username = msg.substr(split1 + 1, split2 - split1 - 1);
			std::string sendMessage = msg.substr(split2 + 1);

			//invalid command or not
			if (split1 != std::string::npos && split2 != std::string::npos) {
				//match socket to sending socket
				SOCKET recipientSocket = INVALID_SOCKET;
				for (const auto& pair : usernames) {
					if (pair.second == username) {
						recipientSocket = pair.first;
						break;
					}
				}
				//send message to specific socket
				if (recipientSocket != INVALID_SOCKET) {
					char* cMsg = new char[sendMessage.length() + 1];
					strcpy(cMsg, sendMessage.c_str());
					if (recipientSocket == clientSocket) {
						return "Messages cannot be sent to yourself";
					}
					int bytesSent = server.sendMessage(recipientSocket, cMsg, sendMessage.length() + 1);
					delete[] cMsg;
					if (bytesSent != 0) {
						return "Failed to send message to user: " + username;
					}
					else {
						return "Direct Message to " + username + ": " + sendMessage;
					}
				}
				else {
					return "User not found: " + username;
				}
			}
			else {
				//invalid command format
				return "Invalid format for send command. Usage: " + cmdChar + "send (username) (message)";
			}
		}
		else if (message[0] == commandChar && strncmp(message + 1, "logout", 6) == 0) {
			//extract name
			std::string msg(message);
			size_t split1 = msg.find(' ', 6);
			std::string username = msg.substr(split1 + 1);

			if (split1 != std::string::npos) {

				//username exist or not
				if ("" == hashTable.get(username)) {
					return "Username does not exist, cannot logout";
				}

				//username login checks
				auto it = std::find_if(usernames.begin(), usernames.end(),
					[&](const auto& entry) { return entry.second == username; });
				if (it != usernames.end()) {
					//check its them
					std::string loggedInUsername = usernames[clientSocket];
					if (loggedInUsername != username) {
						return "You can only log yourself out, nice try..";
					}
					//remove name from list
					usernames.erase(it);
					logouter = "Successfully logged out user: " + username;
					return logouter;
				}
				else {
					return "User is not logged in.";
				}
			}
			else {
				//invalid command format
				return "Invalid format for logout command. Usage: " + cmdChar + "logout (username)";
			}
		}
		else if (message[0] == commandChar && strncmp(message + 1, "getlog", 6) == 0) {
			std::string log = "";
			log = logDB.getMessageLog();
			if (log.empty()) {
				return "No records of user messages";
			}

			//if log is too long, split into chunks
			if (log.size() >= MAX_BUFFER_SIZE) {
				std::vector<std::string> messageChunks;
				const int CHUNK_SIZE = 238; //chunk size, room for end characters and output title
				int numChunks = log.size() / CHUNK_SIZE;
				if (log.size() % CHUNK_SIZE != 0) {
					numChunks++;
				}

				//split log into chunks
				for (int i = 0; i < numChunks; ++i) {
					int startPos = i * CHUNK_SIZE;
					int chunkSize = std::min<int>(log.size() - startPos, CHUNK_SIZE);
					std::string chunk = "Message Log " + std::to_string(i + 1) + ":\n" + log.substr(startPos, chunkSize);
					messageChunks.push_back(chunk);
				}

				//send each chunk
				for (int i = 0; i < messageChunks.size(); i++) {
					int bytesSent = server.sendMessage(clientSocket, const_cast<char*>(messageChunks[i].c_str()), (messageChunks[i].length()));
					if (bytesSent != 0) {
						std::cerr << "Failed to send message chunk\n";
					}
				}

				return "End of Log File";
			}
			//if fits in single buffer, send
			return "Message Log:\n" + log;
		}
		else {
			std::string input = message;
			return input;
		}
	}
	else {
		return "User not logged in. Please use " + cmdChar + "register and " + cmdChar + "login to create an account to start chatting!";
	}
}

int Server::sendMessage(SOCKET clientSocket, char* data, int32_t length)
{
	uint8_t size = static_cast<uint8_t>(length + 1);
	int totalBytesSent = 0;

	//check buffer size to message
	char sendBuffer[MAX_BUFFER_SIZE];
	if (length + 1 + sizeof(size) > MAX_BUFFER_SIZE) {
		return BUFFER_OVERFLOW;
	}

	//buffer adjustments
	memcpy(sendBuffer, &size, sizeof(size));
	memcpy(sendBuffer + sizeof(size), data, length + 1);

	//loop to ensure full data is being sent
	while (totalBytesSent < length + 1 + sizeof(size))
	{
		int bytesSent = send(clientSocket, sendBuffer + totalBytesSent, length + 1 + sizeof(size) - totalBytesSent, 0);
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

void broadcastThreadFunc() {
	//values
	int Bport = 32024;
	const char* Baddr = "255.255.255.255";

	//UDP socket start
	int udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpSocket == INVALID_SOCKET) {
		std::cerr << "Broadcast failed to start" << std::endl;
		return;
	}

	//broadcast address creation
	sockaddr_in broadcastAddr;
	memset(&broadcastAddr, 0, sizeof(broadcastAddr));
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_port = htons(Bport);
	broadcastAddr.sin_addr.s_addr = inet_addr(Baddr);

	//broadcast message dispatch loop
	std::string broadcastMessage = "Server address is: " + std::string(Baddr) + "\nServer Port is: " + std::to_string(Bport);
	while (true) {
		int bytesSent = sendto(udpSocket, broadcastMessage.c_str(), broadcastMessage.length(), 0,
			(sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "Broadcast Error" << std::endl;
		}
		//wait for next broadcast interval
		std::this_thread::sleep_for(std::chrono::seconds(10));
	}

	//finish broadcast
	closesocket(udpSocket);
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
