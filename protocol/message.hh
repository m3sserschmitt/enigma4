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

    void update(const BYTE *data, SIZE datalen)
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);

        this->datalen = datalen;
        memcpy(this->data, data, datalen);
    }

public:
    Message() : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
    }

    Message(const CHAR *data) : data(new BYTE[MESSAGE_MAX_SIZE])
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
        this->setPayload(data);
    }

    Message(const BYTE *data, SIZE datalen) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
        this->setPayload(data, datalen);
    }

    Message(const std::string &data) : data(new BYTE[MESSAGE_MAX_SIZE]), datalen(MESSAGE_HEADER_SIZE)
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
        this->setPayload(data);
    }

    Message(const Message &mb) : data(new BYTE[MESSAGE_MAX_SIZE])
    {
        memset(this->data, 0, MESSAGE_MAX_SIZE);
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

    bool isHandshake() const { return this->hasMessageType(MESSAGE_HANDSHAKE); }

    /**
     * @brief Set the Message Type. It overrides the byte representing message type with
     * value provided into messageType parameter.
     * 
     * @param messageType Message type to be set
     */
    void setMessageType(int messageType)
    {
        BYTES messageTypePtr = this->getMessageTypePtr();
        (*messageTypePtr) = messageType;
    }

    /**
     * @brief Add message type. Previous value is not overriden, istead it uses "|" (or) bitwise operator to add
     * new type.
     * 
     * @param messageType Message type to be added 
     */
    void addMessageType(int messageType)
    {
        BYTES messageTypePtr = this->getMessageTypePtr();
        (*messageTypePtr) |= messageType;
    }

    /**
     * @brief Check if message has specified type.
     * 
     * @param messageType Message type to be checked
     * @return true If message has specified type.
     * @return false If message does not have specified type
     */
    bool hasMessageType(int messageType) const
    {
        BYTES messageTypePtr = this->getMessageTypePtr();
        return ((*messageTypePtr) & messageType) != 0;
    }

    /**
     * @brief Check if message has type passed into checkType parameter. If specified type is present, then newType is added,
     * otherwise message type byte is overriden with newType
     * 
     * @param checkType Type to be checked
     * @param newType New type to be added / set.
     */
    void addIfPressentOrOverrideMessageType(int checkType, int newType)
    {
        if (this->hasMessageType(checkType))
        {
            this->addMessageType(newType);
        }
        else
        {
            this->setMessageType(newType);
        }
    }

    void makeExitSignal()
    {
        this->setMessageType(MESSAGE_EXIT);
    };

    bool isExitSignal() const
    {
        return this->hasMessageType(MESSAGE_EXIT);
    }

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
