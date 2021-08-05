#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include <string>
#include <cryptography/cryptography.hh>

class MessageBuilder
{
    static const SIZE message_max_size = 4096;
    BYTES data;
    SIZE offset;

    static SIZE calculate_offset(SIZE datalen) { return MessageBuilder::message_max_size - datalen; };
    SIZE get_datalen() const { return MessageBuilder::message_max_size - this->offset; };

    BYTE *get_data_start() const { return this->data + this->offset; };
    int set_iv(AES_CRYPTO ctx);

public:
    MessageBuilder() : data(new BYTE[this->message_max_size]), offset(MessageBuilder::message_max_size){};
    MessageBuilder(const CHAR *data);
    MessageBuilder(const std::string &data);
    MessageBuilder(const BYTE *data, SIZE datalen);
    MessageBuilder(const MessageBuilder &mb);

    ~MessageBuilder() { delete[] data; };

    void update(const CHAR *data);
    void update(const std::string &data);
    void update(const BYTE *data, SIZE datalen);

    void set_dest_address(const BYTE *address, SIZE addrlen);
    void set_dest_address(RSA_CRYPTO ctx);

    int encrypt(AES_CRYPTO ctx);
    int encrypt(RSA_CRYPTO ctx);

    const BYTE *get_data(SIZE &datalen) const
    {
        datalen = this->get_datalen();
        return this->get_data_start();
    }

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
