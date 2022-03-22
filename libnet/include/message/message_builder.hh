#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include "cryptography/cryptography.hh"

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
    
    void setId(const BYTE *id)
    {
        if (id)
        {
            this->appendPayloadBeg(id, SESSION_ID_SIZE);
        }
    }

    int encrypt(NetworkNode *route);

    /**
     * @brief Create Phase One hanshake messagage
     * 
     * @param sessionKey Session key to be used for encryption
     * @param rsaencrctx RSA context for session key encryption
     * @return int 0 for success, -1 if failure
     */
    int handshakePhaseOneRequest(const BYTE *sessionKey, const std::string &pubkeypem, RSA_CRYPTO rsaencrctx, AES_CRYPTO ctx);

    int handshakePhaseOneResponse(const BYTE *sessionId, const BYTE *test, AES_CRYPTO aesctx);

    /**
     * @brief Create Phase Two handshake message
     * 
     * @param sessionId Session id returned from server in handshake phase one
     * @param test Test phrase used for authentication returned from server in hanshake phase one
     * @param signctx RSA context used for test phrase signing
     * @return int 0 if success, -1 if failure;
     */
    int handshakePhaseTwoRequest(const BYTE *sessionId, const BYTE *test, RSA_CRYPTO signctx);
    
    int handshakePhaseTwoResponse()
    {
        this->setMessageType(MESSAGE_HANDSHAKE_COMPLETE);

        return 0;
    }

    int addSessionMessage(const BYTE *sessionId, const BYTE *sessionKey, RSA_CRYPTO rsaencrctx);

    int performGuardHandhsake(NetworkNode *guardNode);

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
