#include "LogDatabase.h"
#include <fstream>
#include <iostream>

LogDatabase::LogDatabase(const std::string& commandLogFilename, const std::string& messageLogFilename)
    : commandLogFilename(commandLogFilename), messageLogFilename(messageLogFilename) {}

LogDatabase::~LogDatabase() {}

void LogDatabase::logCommand(const std::string& command) {
    std::ofstream commandLogFile(commandLogFilename, std::ios::app);
    commandLogFile << command << std::endl;
}

void LogDatabase::logMessage(const std::string& message) {
    std::ofstream messageLogFile(messageLogFilename, std::ios::app);
    messageLogFile << message << std::endl;
}

std::string LogDatabase::getCommandLog() {
    std::ifstream file(commandLogFilename);
    std::string log;
    std::string line;
    while (std::getline(file, line)) {
        log += line + "\n";
    }
    file.close();
    return log;
}

std::string LogDatabase::getMessageLog() {
    std::ifstream file(messageLogFilename);
    std::string log;
    std::string line;
    while (std::getline(file, line)) {
        log += line + "\n";
    }
    file.close();
    return log;
}