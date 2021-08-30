#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include <string>
#include <string.h>
#include <cryptography/cryptography.hh>

class MessageBuilder
{
    static const SIZE message_max_size = 4096;
    BYTES data;
    SIZE datalen;
    bool next_required;

    int set_iv(AES_CRYPTO ctx);

public:
    MessageBuilder() : data(new BYTE[this->message_max_size]), datalen(0), next_required(0){};
    MessageBuilder(const CHAR *data);
    MessageBuilder(const std::string &data);
    MessageBuilder(const BYTE *data, SIZE datalen);
    MessageBuilder(const MessageBuilder &mb);

    ~MessageBuilder() { delete[] data; };

    void update(const CHAR *data);
    void update(const std::string &data);
    void update(const BYTE *data, SIZE datalen);

    void append_data(const BYTE *data, SIZE datalen)
    {
        memcpy(this->data + datalen, this->data, this->datalen);
        memcpy(this->data, data, datalen);

        this->datalen += datalen;
    }

    void enable_next(bool enable)
    {
        next_required = enable;
    }
    void set_next(const BYTE *address)
    {
        if (address and this->next_required)
        {
            this->append_data(address, 32);
        }
    }
    void set_id(const BYTE *id)
    {
        if (id)
        {
            this->append_data(id, 16);
        }
    }

    int encrypt(AES_CRYPTO ctx);
    int encrypt(RSA_CRYPTO ctx);

    const BYTE *get_data(SIZE &datalen) const
    {
        datalen = this->datalen;
        return this->data;
    }
    const BYTE *get_data() const { return this->data; };
    SIZE get_datalen() const { return this->datalen; };

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
