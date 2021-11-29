#ifndef MESSAGE_HH
#define MESSAGE_HH

#include <string.h>
#include "../libcryptography/include/cryptography.hh"

#include "message_const.hh"

class Message
{
    BYTES data;
    SIZE datalen;

protected:
    
    BYTES getDataPtr()
    {
        return this->data;
    }

    BYTES getMessageTypePtr() const
    {
        return this->data + MESSAGE_ENC_ALGORITHM_OFFSET;
    }

    BYTES getPayloadSizePtr() const
    {
        return this->data + MESSAGE_SIZE_SECTION_OFFSET;
    }
    
    BYTES getPayloadPtr() const
    {
        return this->data + MESSAGE_PAYLOAD_OFFSET;
    }

    void setPayloadSize(SIZE size)
    {
        (this->data + MESSAGE_SIZE_SECTION_OFFSET)[0] = size >> 8;
        (this->data + MESSAGE_SIZE_SECTION_OFFSET)[1] = size;
        this->datalen = size + MESSAGE_HEADER_SIZE;
    }

    void setDatalen(SIZE datalen)
    {
        this->datalen = datalen;
    }

    void increasePayloadSize(SIZE size)
    {
        this->setPayloadSize(this->getPayloadSize() + size);
    }

    void decreasePayloadSize(SIZE size)
    {
        this->setPayloadSize(this->getPayloadSize() - size);
    }

    void increaseDatalen(SIZE size)
    {
        this->datalen += size;
    }

    void setMessageType(int algorithm)
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
        this->setPayload(data);
    }

    Message(const BYTE *data, SIZE datalen) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        this->setPayload(data, datalen);
    }

    Message(const std::string &data) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        this->setPayload(data);
    }
    
    Message(const Message &mb) : data(new BYTE[MESSAGE_MAX_SIZE])
    {
        this->update(mb.data, mb.datalen);
    }

    virtual ~Message() = 0;

    int getMessageType() const
    {
        return *this->getMessageTypePtr();
    }

    const BYTE *getPayload(SIZE &payloadlen) const
    {
        payloadlen = this->getPayloadSize();
        return this->getPayloadPtr();
    }

    const BYTE *getPayload() const
    {
        return this->getPayloadPtr();
    }

    SIZE getPayloadSize() const
    {
        return this->datalen - MESSAGE_HEADER_SIZE;
    }

    void setPayload(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->getPayloadPtr();
        // memset(payload, 0, this->getPayloadSize());
        memcpy(payload, data, datalen);
        this->setPayloadSize(datalen);
    }

    void setPayload(const CHAR *data)
    {
        this->setPayload((BYTES)data, strlen(data));
    }

    void setPayload(const std::string &data)
    {
        this->setPayload(data.c_str());
    }

    bool isHandshake() const { return this->getMessageType() == MESSAGE_HANDSHAKE; }

    bool isExit() const { return this->getMessageType() == MESSAGE_EXIT; }

    const BYTE *getData(SIZE &datalen) const
    {
        datalen = this->datalen;
        return this->data;
    }

    const BYTE *getData() const
    {
        return this->data;
    };

    SIZE getDatalen() const
    {
        return this->datalen;
    };

    void reset()
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
        datalen = 0;
    }

    Message &operator=(const Message &mb);
};

#endif
