#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include <cryptography/cryptography.hh>

#include "../onion_routing/session.hh"

#include "../onion_routing/route.hh"

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

    static SIZE read_payload_size(const BYTE *data)
    {
        const BYTE *payload_size_ptr = data + MESSAGE_SIZE_SECTION_OFFSET;
        SIZE payload_size = *payload_size_ptr;

        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }

    int decrypt(AES_CRYPTO ctx);

    void parse(const CHAR *data);

public:
    MessageParser() : Message(){};
    MessageParser(const CHAR *data) : Message(data) {}
    MessageParser(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageParser(const std::string &data) : Message(data) {}
    MessageParser(const MessageParser &mp) : Message(mp), parseddata(mp.parseddata){};
    ~MessageParser(){};

    SIZE update(const BYTE *data, SIZE datalen)
    {
        datalen = std::min(datalen, this->read_payload_size(data) + MESSAGE_HEADER_SIZE);
        Message::update(data, datalen);
        return datalen;
    }

    SIZE get_required_size() const
    {
        return this->get_payload_size() - this->get_actual_payload_size();
    }

    SIZE append_payload(const BYTE *data, SIZE datalen)
    {
        SIZE payload_size = this->get_payload_size();

        datalen = std::min(this->get_required_size(), datalen);

        memcpy(this->get_payload_ptr() + payload_size, data, datalen);
        this->set_payload_size(payload_size + datalen);
        return datalen;
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

    const std::string &get_parsed_id() { return this->parseddata["id"]; }
    const std::string &get_parsed_address() { return this->parseddata["address"]; }
    const std::string &get_parsed_next_address() { return this->parseddata["next"]; }

    bool parsed_id_exists() const { return this->key_exists("id"); }
    bool parsed_address_exists() const { return this->key_exists("address"); }
    bool parsed_next_address_exists() const { return this->key_exists("next"); }

    bool is_complete() const
    {
        return not this->get_required_size();
    }

    int decrypt(Route *r);
    int decrypt(SessionManager *s);

    int handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx);

    void remove_next();
    void remove_id();

    void parse() { this->parse((const CHAR *)this->get_payload_ptr()); }
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
