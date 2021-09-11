#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include <string>
#include <string.h>
#include <cryptography/cryptography.hh>

#include "message.hh"

class MessageBuilder : public Message
{
    void append_payload_beg(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->get_payload_ptr();
        SIZE payload_size = this->get_payload_size();

        memcpy(payload + datalen, payload, payload_size);
        memcpy(payload, data, datalen);

        this->set_payload_size(payload_size + datalen);
    }

public:
    MessageBuilder() : Message(){};
    MessageBuilder(const CHAR *data) : Message(data) {}
    MessageBuilder(const std::string &data) : Message(data) {}
    MessageBuilder(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageBuilder(const MessageBuilder &mb) : Message(mb) {}

    ~MessageBuilder(){};

    void set_next(const BYTE *address)
    {
        if (address)
        {
            this->append_payload_beg(address, MESSAGE_ADDRESS_SIZE);
        }
    }
    void set_id(const BYTE *id)
    {
        if (id)
        {
            this->append_payload_beg(id, MESSAGE_ID_SIZE);
        }
    }

    int encrypt(AES_CRYPTO ctx);
    int encrypt(RSA_CRYPTO ctx);

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
