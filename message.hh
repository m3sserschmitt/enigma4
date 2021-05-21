#ifndef MESSAGE_H
#define MESSAGE_H

#include <map>
#include <string>

class Message {
    std::map<std::string, std::string> data;

public:
    Message();
    Message(std::string data);

    void update(std::string data);

    std::string operator[](std::string key);
};

#endif