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

    std::map<std::string, std::string> data;

    void shift_left(SIZE len)
    {
        this->datalen -= len;
        memcpy(this->rawdata, this->rawdata + len, this->datalen);
        memset(this->rawdata + this->datalen, 0, len);
    }

public:
    MessageParser() : rawdata(new BYTE[this->max_message_size]), datalen(0){};

    MessageParser(const MessageParser &mp);
    ~MessageParser() { delete this->rawdata; };

    void update(const BYTE *data, SIZE datalen);
    int decrypt(AES_CRYPTO ctx);
    int decrypt(RSA_CRYPTO ctx);

    void remove_next();
    void remove_id();

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

    const BYTE *get_data(SIZE &datalen) const
    {
        datalen = this->datalen;
        return this->rawdata;
    };
    const BYTE *get_data() const { return this->rawdata; }
    SIZE get_datalen() const { return this->datalen; };

    MessageParser &operator=(const MessageParser &mp);
    std::string &operator[](const std::string &key);
};

#endif
