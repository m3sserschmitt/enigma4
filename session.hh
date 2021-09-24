#ifndef SESSION_HH
#define SESSION_HH

#include <map>
#include <string>
#include <cryptography/cryptography.hh>

class MessageParser;

class Session
{
    std::map<std::string, AES_CRYPTO> keys;

    Session(const Session &);
    const Session &operator=(const Session &);

public:
    Session() {}

    int setup(RSA_CRYPTO rsactx, MessageParser &mp);
    AES_CRYPTO get_ctx(const std::string &id) { return this->keys[id]; }
};

#endif