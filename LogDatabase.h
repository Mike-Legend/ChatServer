#include <string>

class LogDatabase {
private:
    std::string commandLogFilename;
    std::string messageLogFilename;

public:
    LogDatabase(const std::string& commandLogFilename, const std::string& messageLogFilename);
    ~LogDatabase();

    void logCommand(const std::string& command);
    void logMessage(const std::string& message);

    std::string getCommandLog();
    std::string getMessageLog();
};