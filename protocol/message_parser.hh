#ifndef MESSAGE_PARSER_HH
#define MESSAGE_PARSER_HH

#include <map>
#include "../libcryptography/include/cryptography.hh"

#include "../onion_routing/route.hh"

#include "message.hh"

#include "../types/map_types.hh"

class Connection;

class MessageParser : public Message
{
    Dictionary parseddata;

    /*void removePayloadBeg(SIZE len)
    {
        BYTES payload = this->getPayloadPtr();
        SIZE payload_size = this->getPayloadSize();

        memcpy(payload, payload + len, payload_size);
        payload_size -= len;
        memset(payload + payload_size, 0, len);
    }*/

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

        const BYTE *address_ptr = messsageRawData + MESSAGE_PAYLOAD_OFFSET;

        PLAINTEXT next = 0;
        CRYPTO::hex(address_ptr, MESSAGE_ADDRESS_SIZE, &next);

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

    /**
     * @brief Decrypt session key from handshake message
     * 
     * @param rsactx Local initialized RSA context used for decryption
     * @param aesctx AES context to be initialized with decrypted session key
     * @return int 0 if success, -1 if failure
     */
    int handshakeDecryptSessionKey(RSA_CRYPTO rsactx, AES_CRYPTO aesctx);

    /**
     * @brief Decrypt client public key from handhsake message
     * 
     * @param aesctx Initialized AES context for decryption
     * @param rsactx RSA context to be initialized with decrypted public key for 
     * signature verification
     * @return int 0 if success, -1 if failure
     */
    int handshakeDecryptPubkey(AES_CRYPTO aesctx, RSA_CRYPTO rsactx);

    /**
     * @brief Perform message signature verification
     * 
     * @param rsactx Initialized RSA context for to be used for verification
     * @return int 0 if success, -1 if failure.
     */
    int messageVerifySignature(RSA_CRYPTO rsactx);

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

    /* static SIZE computeTotalMessageSize(const BYTE *data)
    {
        return MessageParser::readPayloadSize(data) + MESSAGE_HEADER_SIZE;
    } */

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
    int removeEncryptionLayer(NodesMap *nodes);

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

    int handshake(RSA_CRYPTO rsactx, NetworkNode *route);

    int handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx);

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
