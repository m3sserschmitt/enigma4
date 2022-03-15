#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include <string.h>

#include "../../libcryptography/include/cryptography.hh"

#include "../network_node.hh"

#include "message.hh"

//#include "../../types/map_types.hh"

class Connection;

class MessageParser : public Message
{
    std::map<std::string, std::string> parseddata;

    /**
     * @brief Extract next address from message raw data
     * (used internally by removeEncryptionLayer method).
     *
     * @param messsageRawData Message byte array representation
     */
    void parseNextAddress(const BYTE *messsageRawData)
    {
        if (this->parsedNextAddressExists())
        {
            return;
        }

        PLAINTEXT next = 0;
        CRYPTO::hex(messsageRawData, MESSAGE_ADDRESS_SIZE, &next);

        this->parseddata["next"] = next;

        delete[] next;
        next = 0;

        return;
    }

    void reconstructNextMessage(BYTES decryptedPayload, SIZE decryptedPayloadSize)
    {
        // copy header of resulted message after encryption layer was removed
        memcpy(this->getDataPtr(), decryptedPayload, MESSAGE_HEADER_SIZE);

        SIZE skippedBytes = MESSAGE_HEADER_SIZE + MESSAGE_ADDRESS_SIZE;
        SIZE remainingBytes = decryptedPayloadSize - skippedBytes;

        // copy resulted message payload, skipping next address
        memcpy(this->getPayloadPtr(), decryptedPayload + skippedBytes, remainingBytes);

        this->setPayloadSize(remainingBytes);
        this->setDatalen(decryptedPayloadSize - MESSAGE_ADDRESS_SIZE);
    }

    /**
     * @brief Extract session ID
     * (used internally by removeEncryptionLayerMethod and handshake methods).
     */
    void parseSessionID()
    {
        if (this->parsedIdExists())
        {
            return;
        }

        BASE64 id = new CHAR[ENCODED_SESSION_ID_SIZE + 1];
        CRYPTO::base64_encode(this->getPayloadPtr(), SESSION_ID_SIZE, &id);

        this->parseddata["id"] = id;
    }

    void parseSessionId(const BYTE *sessionId)
    {
        BASE64 encodedSessionId = 0;
        CRYPTO::base64_encode(sessionId, SESSION_ID_SIZE, &encodedSessionId);

        this->parseddata["id"] = encodedSessionId;

        delete[] encodedSessionId;
        encodedSessionId = 0;
    }

    /**
     * @brief Perform decryption on message payload and call parseNextAddress method
     * in order to parse next address
     *
     * @param ctx AES context used for decryption
     * @return int 0 if success, -1 if failure
     */
    int decrypt(AES_CRYPTO ctx);

    /**
     * @brief Parse plaintext key value data
     *
     * @param data Data to be parsed
     */
    void parse(const CHAR *data);

public:
    MessageParser() : Message(){};

    MessageParser(const CHAR *data) : Message(data) {}

    MessageParser(const BYTE *data, SIZE datalen) : Message(data, datalen) {}

    MessageParser(const std::string &data) : Message(data) {}

    MessageParser(const MessageParser &mp) : Message(mp), parseddata(mp.parseddata){};

    ~MessageParser(){};

    /**
     * @brief Read payload size from message byte array representation
     *
     * @param data Byte array containing message to read from
     * @return SIZE Message payload size
     */
    static SIZE readPayloadSize(const BYTE *data)
    {
        const BYTE *payload_size_ptr = data + MESSAGE_SIZE_SECTION_OFFSET;
        SIZE payload_size = *payload_size_ptr;

        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }

    /**
     * @brief Update object with provided data. This method overrides all existing data
     *
     * @param data Byte array representing a message
     * @param datalen Messag data size
     * @return SIZE Number of bytes read
     * (if more data than required was passed, the rest is ignored)
     */
    SIZE update(const BYTE *data, SIZE datalen)
    {
        datalen = std::min(datalen, this->readPayloadSize(data) + MESSAGE_HEADER_SIZE);
        Message::update(data, datalen);
        return datalen;
    }

    /**
     * @brief Get the required bytes to complete the message
     *
     * @return SIZE
     */
    SIZE getRequiredSize() const
    {
        return this->getPayloadSize() - this->getActualPayloadSize();
    }

    /**
     * @brief Append provided data to existing payload. If more data than required
     * id passed, the rest is ignored
     *
     * @param data Data to be appended
     * @param datalen Size of data to be appended
     * @return SIZE Number of bytes appended
     */
    SIZE appendPayload(const BYTE *data, SIZE datalen)
    {
        datalen = std::min(this->getRequiredSize(), datalen);

        memcpy(this->getDataPtr() + this->getDatalen(), data, datalen);

        this->increaseDatalen(datalen);

        return datalen;
    }

    /**
     * @brief Get the Payload Size read from message header
     *
     * @return SIZE
     */
    SIZE getPayloadSize() const
    {
        BYTES payload_size_ptr = this->getPayloadSizePtr();
        SIZE payload_size = *payload_size_ptr;
        payload_size <<= 8;
        payload_size |= *(payload_size_ptr + 1);

        return payload_size;
    }

    /**
     * @brief Get the Actual Payload Size. The object can contain more or
     * less bytes than required
     *
     * @return SIZE real size of message payload in bytes
     */
    SIZE getActualPayloadSize() const
    {
        return Message::getPayloadSize();
    }

    const std::string &getParsedId() { return this->parseddata["id"]; }

    const std::string &getParsedNextAddress() { return this->parseddata["next"]; }

    bool parsedIdExists() const { return this->keyExists("id"); }

    bool parsedNextAddressExists() const { return this->keyExists("next"); }

    bool isComplete() const
    {
        if (this->hasType(MESSAGE_INITIAL_STATE))
        {
            return false;
        }

        return not this->getRequiredSize();
    }

    bool isBroadcast() const { return this->hasType(MESSAGE_BRADCAST); }

    void broadcast()
    {
        this->parseSessionID();
        this->parseNextAddress(this->getPayload() + SESSION_ID_SIZE);
    }

    /**
     * @brief Removes one encryption layer. This method internally calls parseSessionId
     * and parseNextAddress. When an encryption layer is removed, session ID and
     * message next destination will be parsed
     *
     * @param nodes Pointer to nodes map used to lookup for required NetworkNode structure
     * for decryption. Every NetworkNode structure contain its own initialized AES context
     * used for decryption
     * @return int 0 if success, -1 if failure
     */
    int removeEncryptionLayer(std::map<std::string, NetworkNode *> *nodes);

    /**
     * @brief Removes one encryption layer. This method internally calls parseSessionId
     * and parseNextAddress. When an encryption layer is removed, session ID and
     * message next destination will be parsed
     *
     * @param conn Pointer to Connection structure to lookup for
     * session with corresponding ID. Every session contain an initialized AES context
     * for decryption
     * @return int 0 if success, -1 if failure
     */
    int removeEncryptionLayer(Connection *conn);

    int handshakePhaseOneRequest(RSA_CRYPTO rsadecrctx, AES_CRYPTO ctx, std::string &pubkeypem) const;

    int handshakePhaseOneResponse(AES_CRYPTO aesctx, BYTES *sessionId, BYTES *test) const;

    int handshakePhaseTwoRequest(RSA_CRYPTO rsaverifctx, const BYTE *sessionId, const BYTE *test) const;

    int handshakePhaseTwoResponse() const
    {
        return this->hasType(MESSAGE_HANDSHAKE_COMPLETE) ? 0 : -1;
    }

    int addSessionMessage(RSA_CRYPTO decrctx, BYTES *sessionId, BYTES *sessionKey);

    void parse() { this->parse((const CHAR *)this->getPayloadPtr()); }

    bool keyExists(const std::string &key) const
    {
        return this->parseddata.find(key) != this->parseddata.end();
    };

    void reset()
    {
        this->parseddata.clear();
        Message::reset();
    };

    MessageParser &operator=(const MessageParser &mp)
    {
        if (this != &mp)
        {
            this->parseddata = mp.parseddata;
        }

        Message::operator=(mp);

        return *this;
    }

    std::string &operator[](const std::string &key)
    {
        return this->parseddata[toLowercase(key)];
    }
};

#endif
