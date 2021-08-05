#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include <string>
#include <string.h>
#include <cryptography/types.hh>

class MessageParser
{
    static const SIZE max_message_size = 4096;

    BYTES rawdata;
    SIZE datalen;

    // BYTES next_addr;

    std::map<std::string, std::string> data;
    
public:
    MessageParser() : rawdata(new BYTE[this->max_message_size]), datalen(0){};

    MessageParser(const MessageParser &mp);
    ~MessageParser() { delete this->rawdata; };

    void update(const BYTE *data, SIZE datalen);
    int decrypt(AES_CRYPTO ctx);
    int decrypt(RSA_CRYPTO ctx);

    void parse();
    bool key_exists(const std::string &key) const
    {
        return this->data.find(key) != this->data.end();
    };
    void clear()
    {
        this->data.clear();
        memset(this->rawdata, 0, this->max_message_size);
        datalen = 0;
    };

    MessageParser &operator=(const MessageParser &mp);
    std::string &operator[](const std::string &key);
};

#endif
