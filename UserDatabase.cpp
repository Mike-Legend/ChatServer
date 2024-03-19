#include "UserDatabase.h"

UserDatabase::UserDatabase() : table(TABLE_SIZE) {}
UserDatabase::~UserDatabase() {}

int UserDatabase::hash(const std::string& key) {
    int hash = 0;
    for (char c : key) {
        hash += c;
    }
    return hash % TABLE_SIZE;
}

void UserDatabase::insert(const std::string& key, const std::string& value) {
    int index = hash(key);
    table[index].push_back({ key, value });
    //store table to file at some point
}

std::string UserDatabase::get(const std::string& key) {
    int index = hash(key);
    for (const auto& pair : table[index]) {
        if (pair.first == key) {
            return pair.second;
        }
    }
    return "";
}

void UserDatabase::remove(const std::string& key) {
    int index = hash(key);
    table[index].remove_if([&key](const auto& pair) { return pair.first == key; });
}
