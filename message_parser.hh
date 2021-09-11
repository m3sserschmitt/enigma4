#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include <string>
#include <string.h>
#include <cryptography/types.hh>

#include "message.hh"

class MessageParser : public Message
{
    std::map<std::string, std::string> parseddata;
    
    void remove_payload_beg(SIZE len)
    {
        BYTES payload = this->get_payload_ptr();
        SIZE payload_size = this->get_payload_size();

        memcpy(payload, payload + len, payload_size);
        payload_size -= len;
        memset(payload + payload_size, 0, len);    
    }

public:
    MessageParser() : Message(){};
    MessageParser(const CHAR *data) : Message(data) {}
    MessageParser(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageParser(const std::string &data) : Message(data) {}
    MessageParser(const MessageParser &mp) : Message(mp), parseddata(mp.parseddata){};
    ~MessageParser(){};

    void update(const BYTE *data, SIZE datalen)
    {
        Message::update(data, datalen);
    }

    void append_payload(const BYTE *data, SIZE datalen)
    {
        SIZE payload_size = this->get_payload_size();
        memcpy(this->get_payload_ptr() + payload_size, data, datalen);
        this->set_payload_size(payload_size + datalen);
    }
    SIZE get_payload_size() const
    {
        BYTES payload_size_ptr = this->get_payload_size_ptr();
        SIZE payload_size = *payload_size_ptr;
        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }
    SIZE get_actual_payload_size() const
    {
        return Message::get_payload_size();
    }

    int decrypt(AES_CRYPTO ctx);
    int decrypt(RSA_CRYPTO ctx);

    void remove_next();
    void remove_id();

    void parse();
    bool key_exists(const std::string &key) const
    {
        return this->parseddata.find(key) != this->parseddata.end();
    };
    void clear()
    {
        this->parseddata.clear();
        Message::clear();
    };

    MessageParser &operator=(const MessageParser &mp);
    std::string &operator[](const std::string &key);
};

#endif
