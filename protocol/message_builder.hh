#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include "../libcryptography/include/cryptography.hh"

#include "message.hh"

class NetworkNode;

class MessageBuilder : public Message
{
    void appendPayloadBeg(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->getPayloadPtr();
        SIZE payload_size = this->getPayloadSize();

        memcpy(payload + datalen, payload, payload_size);
        memcpy(payload, data, datalen);

        this->setPayloadSize(payload_size + datalen);
    }

    void appendPayloadEnd(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->getPayloadPtr();
        SIZE payload_size = this->getPayloadSize();

        memcpy(payload + payload_size, data, datalen);
        this->setPayloadSize(payload_size + datalen);
    }

    int encrypt(AES_CRYPTO ctx);

    int handshakeSetupSessionKey(NetworkNode *route);
    // int handshake_setup_session_key(AES_CRYPTO aesctx, RSA_CRYPTO rsactx);
    int handshakeSetupPubkey(AES_CRYPTO ctx, const std::string &pubkeypem);
    int signMessage(RSA_CRYPTO ctx);

public:
    MessageBuilder() : Message(){};
    MessageBuilder(const CHAR *data) : Message(data) {}
    MessageBuilder(const std::string &data) : Message(data) {}
    MessageBuilder(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageBuilder(const MessageBuilder &mb) : Message(mb) {}

    ~MessageBuilder(){};

    void setNext(const BYTE *address)
    {
        if (address)
        {
            this->appendPayloadBeg(address, MESSAGE_ADDRESS_SIZE);
        }
    }
    void set_id(const BYTE *id)
    {
        if (id)
        {
            this->appendPayloadBeg(id, MESSAGE_ID_SIZE);
        }
    }

    int encrypt(NetworkNode *route);

    // int handshake(AES_CRYPTO aesctx, RSA_CRYPTO encrrsactx, RSA_CRYPTO signrsactx = 0, const std::string &pubkeypem = "");
    int handshake(NetworkNode *route, RSA_CRYPTO signrsactx = 0, const std::string &pubkeypem = "");
    
    void exitCircuit() { this->setMessageType(MESSAGE_EXIT); };

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
