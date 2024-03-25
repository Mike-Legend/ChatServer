#pragma once
#include <string>
#include <list>
#include <vector>

class UserDatabase {
private:
    int size;
    static const int TABLE_SIZE = 100;
    std::vector<std::list<std::pair<std::string, std::string>>> table;
    int hash(const std::string& key);

public:
    int getSize() const {return size;}
    UserDatabase();
    ~UserDatabase();

    void insert(const std::string& key, const std::string& value);
    std::string get(const std::string& key);
    void remove(const std::string& key);
};
