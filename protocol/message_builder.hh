#ifndef MESSAGE_BUILDER_HH
#define MESSAGE_BUILDER_HH

#include "../libcryptography/include/cryptography.hh"

#include "message.hh"

class Route;

class MessageBuilder : public Message
{
    void append_payload_beg(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->get_payload_ptr();
        SIZE payload_size = this->get_payload_size();

        memcpy(payload + datalen, payload, payload_size);
        memcpy(payload, data, datalen);

        this->set_payload_size(payload_size + datalen);
    }

    void append_payload_end(const BYTE *data, SIZE datalen)
    {
        BYTES payload = this->get_payload_ptr();
        SIZE payload_size = this->get_payload_size();

        memcpy(payload + payload_size, data, datalen);
        this->set_payload_size(payload_size + datalen);
    }

    int encrypt(AES_CRYPTO ctx);

    int handshake_setup_session_key(Route *route, bool add_all_keys);
    // int handshake_setup_session_key(AES_CRYPTO aesctx, RSA_CRYPTO rsactx);
    int handshake_setup_pubkey(AES_CRYPTO ctx, const std::string &pubkeypem);
    int sign_message(RSA_CRYPTO ctx);

public:
    MessageBuilder() : Message(){};
    MessageBuilder(const CHAR *data) : Message(data) {}
    MessageBuilder(const std::string &data) : Message(data) {}
    MessageBuilder(const BYTE *data, SIZE datalen) : Message(data, datalen) {}
    MessageBuilder(const MessageBuilder &mb) : Message(mb) {}

    ~MessageBuilder(){};

    void set_next(const BYTE *address)
    {
        if (address)
        {
            this->append_payload_beg(address, MESSAGE_ADDRESS_SIZE);
        }
    }
    void set_id(const BYTE *id)
    {
        if (id)
        {
            this->append_payload_beg(id, MESSAGE_ID_SIZE);
        }
    }

    int encrypt(Route *route);

    // int handshake(AES_CRYPTO aesctx, RSA_CRYPTO encrrsactx, RSA_CRYPTO signrsactx = 0, const std::string &pubkeypem = "");
    int handshake(Route *route, RSA_CRYPTO signrsactx = 0, const std::string &pubkeypem = "", bool add_all_keys = 0);
    
    void exit_circuit() { this->set_message_type(MESSAGE_EXIT); };

    MessageBuilder &operator=(const MessageBuilder &mb);
};

#endif
