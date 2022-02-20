#ifndef SESSION_HH
#define SESSION_HH

#include <map>
#include <string>
#include "../libcryptography/include/cryptography.hh"

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

        CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx);
        CRYPTO::AES_init_ctx(DECRYPT, this->aesctx);
    }

    ~SessionManager()
    {
        std::map<std::string, AES_CRYPTO>::iterator it = keys.begin();
        std::map<std::string, AES_CRYPTO>::iterator it_end = keys.end();

        for (; it != it_end; it++)
        {
            CRYPTO::AES_CRYPTO_free_keys(it->second);
        }

        CRYPTO::AES_CRYPTO_free(this->aesctx);
    }

    AES_CRYPTO getEncryptionContext(const std::string &id) { return this->keys[id]; }

    int set(const BYTE *sessionId, const BYTE *sessionKey);

    void cleanup(const std::string &id)
    {
        CRYPTO::AES_CRYPTO_free(keys[id]);
        keys.erase(id);
    }
    
    AES_CRYPTO operator[](const std::string &id)
    {
        return this->keys[id];
    }
};

#endif