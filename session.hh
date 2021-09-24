#ifndef SESSION_HH
#define SESSION_HH

#include <map>
#include <string>
#include <cryptography/cryptography.hh>

class MessageParser;

class SessionManager
{
    AES_CRYPTO aesctx;

    std::map<std::string, AES_CRYPTO> keys;

    SessionManager(const SessionManager &);
    const SessionManager &operator=(const SessionManager &);

public:
    SessionManager()
    {
        this->aesctx = CRYPTO::AES_CRYPTO_new();

        CRYPTO::AES_iv_autoset(1, this->aesctx);
        CRYPTO::AES_iv_append(1, this->aesctx);

        CRYPTO::AES_init(0, 0, 0, 0, this->aesctx);
    }
    ~SessionManager()
    {
        CRYPTO::AES_CRYPTO_free(this->aesctx);
    }

    int setup(RSA_CRYPTO rsactx, MessageParser &mp);
    AES_CRYPTO get_ctx(const std::string &id) { return this->keys[id]; }

    void set(const std::string &id, AES_CRYPTO aesctx) { this->keys[id] = aesctx; }
};

#endif