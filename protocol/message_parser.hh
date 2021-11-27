#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include "../libcryptography/include/cryptography.hh"

#include "../onion_routing/route.hh"

#include "message.hh"

class Connection;

class MessageParser : public Message
{
    std::map<std::string, std::string> parseddata;

    void removePayloadBeg(SIZE len)
    {
        BYTES payload = this->getPayloadPtr();
        SIZE payload_size = this->getPayloadSize();

        memcpy(payload, payload + len, payload_size);
        payload_size -= len;
        memset(payload + payload_size, 0, len);
    }

    int decrypt(AES_CRYPTO ctx);

    void parse(const CHAR *data);

    int handshakeDecryptSessionKey(RSA_CRYPTO rsactx, AES_CRYPTO aesctx);
    int handshakeDecryptPubkey(AES_CRYPTO aesctx, RSA_CRYPTO rsactx);
    int messageVerifySignature(RSA_CRYPTO rsactx);

public:
    MessageParser() : Message(){};
    MessageParser(const CHAR *data) : Message(data) {}
    MessageParser(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageParser(const std::string &data) : Message(data) {}
    MessageParser(const MessageParser &mp) : Message(mp), parseddata(mp.parseddata){};
    ~MessageParser(){};

    static SIZE readPayloadSize(const BYTE *data)
    {
        const BYTE *payload_size_ptr = data + MESSAGE_SIZE_SECTION_OFFSET;
        SIZE payload_size = *payload_size_ptr;

        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }

    static SIZE computeTotalMessageSize(const BYTE *data)
    {
        return MessageParser::readPayloadSize(data) + MESSAGE_HEADER_SIZE;
    }

    SIZE update(const BYTE *data, SIZE datalen)
    {
        datalen = std::min(datalen, this->readPayloadSize(data) + MESSAGE_HEADER_SIZE);
        Message::update(data, datalen);
        return datalen;
    }

    SIZE getRequiredSize() const
    {
        return this->getPayloadSize() - this->getActualPayloadSize();
    }

    SIZE appendPayload(const BYTE *data, SIZE datalen)
    {
        datalen = std::min(this->getRequiredSize(), datalen);
        
        memcpy(this->getDataPtr() + this->getDatalen(), data, datalen);
        
        this->increaseDatalen(datalen);

        return datalen;
    }

    SIZE getPayloadSize() const
    {
        BYTES payload_size_ptr = this->getPayloadSizePtr();
        SIZE payload_size = *payload_size_ptr;
        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }
    
    SIZE getActualPayloadSize() const
    {
        return Message::getPayloadSize();
    }

    const std::string &getParsedId() { return this->parseddata["id"]; }
    const std::string &getParsedAddress() { return this->parseddata["address"]; }
    const std::string &getParsedNextAddress() { return this->parseddata["next"]; }
    const std::string &getParsedPubkey() { return this->parseddata["pubkey"]; }

    bool parsedIdExists() const { return this->keyExists("id"); }
    bool parsedAddressExists() const { return this->keyExists("address"); }
    bool parsedNextAddressExists() const { return this->keyExists("next"); }
    bool parsedPubkeyExists() const { return this->keyExists("pubkey"); }

    bool isComplete() const
    {
        return this->getPayloadSize() and not this->getRequiredSize();
    }

    int decrypt(NetworkNode *route);

    int decrypt(Connection *conn);

    int handshake(RSA_CRYPTO rsactx, NetworkNode *route);

    int handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx);

    void removeNext();

    void removeId();

    void parse() { this->parse((const CHAR *)this->getPayloadPtr()); }

    bool keyExists(const std::string &key) const
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
