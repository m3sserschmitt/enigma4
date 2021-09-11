#ifndef MESSAGE_HH
#define MESSAGE_HH

#include <string.h>
#include <cryptography/cryptography.hh>

#include "message_const.hh"

class Message
{
    BYTES data;
    SIZE datalen;

protected:
    BYTES get_enc_algorithm_ptr() const
    {
        return this->data + MESSAGE_ENC_ALGORITHM_OFFSET;
    }
    BYTES get_payload_size_ptr() const
    {
        return this->data + MESSAGE_SIZE_SECTION_OFFSET;
    }
    BYTES get_payload_ptr() const
    {
        return this->data + MESSAGE_PAYLOAD_OFFSET;
    }

    void set_payload_size(SIZE size)
    {
        (this->data + MESSAGE_SIZE_SECTION_OFFSET)[0] = size >> 8;
        (this->data + MESSAGE_SIZE_SECTION_OFFSET)[1] = size;
        this->datalen = size + MESSAGE_HEADER_SIZE;
    }
    void set_enc_algorithm(int algorithm)
    {
        *(this->data + MESSAGE_ENC_ALGORITHM_OFFSET) = algorithm;
    }

    void update(const BYTE *data, SIZE datalen)
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);

        this->datalen = datalen;
        memcpy(this->data, data, datalen);
    }

public:
    Message() : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE) {}
    Message(const CHAR *data) : data(new BYTE[MESSAGE_MAX_SIZE])
    {
        this->set_payload(data);
    }
    Message(const BYTE *data, SIZE datalen) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        this->set_payload(data, datalen);
    }
    Message(const std::string &data) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        this->set_payload(data);
    }
    Message(const Message &mb) : data(new BYTE[MESSAGE_MAX_SIZE])
    {
        this->update(mb.data, mb.datalen);
    }

    virtual ~Message() = 0;

    int get_enc_algorithm() const 
    {
        return *this->get_enc_algorithm_ptr();
    }

    const BYTE *get_payload(SIZE &payloadlen) const 
    {
        payloadlen = this->get_payload_size();
        return this->get_payload_ptr();
    }
    const BYTE *get_payload() const
    {
        return this->get_payload_ptr();
    }
    SIZE get_payload_size() const
    {
        return this->datalen - MESSAGE_HEADER_SIZE;
    }

    void set_payload(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->get_payload_ptr();
        memset(payload, 0, this->get_payload_size());
        memcpy(payload, data, datalen);
        this->set_payload_size(datalen);
    }
    void set_payload(const CHAR *data)
    {
        this->set_payload((BYTES)data, strlen(data));
    }
    void set_payload(const std::string &data)
    {
        this->set_payload(data.c_str());
    }

    const BYTE *get_data(SIZE &datalen) const
    {
        datalen = this->datalen;
        return this->data;
    }
    const BYTE *get_data() const
    {
        return this->data;
    };
    SIZE get_datalen() const
    {
        return this->datalen;
    };

    void clear()
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
        datalen = 0;
    }

    Message &operator=(const Message &mb);
};

#endif
