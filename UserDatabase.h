#pragma once
#include <string>
#include <list>
#include <vector>

class UserDatabase {
private:
    static const int TABLE_SIZE = 100;
    std::vector<std::list<std::pair<std::string, std::string>>> table;
    int hash(const std::string& key);

public:
    UserDatabase();
    ~UserDatabase();

    void insert(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    void remove(const std::string& key);
};
