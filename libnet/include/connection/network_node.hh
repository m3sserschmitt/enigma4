#ifndef ROUTE_HH
#define ROUTE_HH

#include "cryptography/cryptography.hh"
#include "util/util.hh"
#include "message/message_const.hh"

#include <string.h>

class NetworkNode
{
    RSA_CRYPTO rsactx;
    AES_CRYPTO aesctx;

    BYTES keyDigest;
    PLAINTEXT keyHexDigest;
    BYTES id;

    NetworkNode *next;
    NetworkNode *previous;

    NetworkNode(const NetworkNode &);
    const NetworkNode &operator=(const NetworkNode &);

public:
    NetworkNode()
    {
        this->next = 0;
        this->previous = 0;

        this->keyDigest = new BYTE[32 + 1];
        this->keyHexDigest = new CHAR[64 + 1];
        this->id = new BYTE[16 + 1];

        memset(this->keyDigest, 0, 32 + 1);
        memset(this->keyHexDigest, 0, 64 + 1);
        memset(this->id, 0, 16 + 1);

        this->rsactx = CRYPTO::RSA_CRYPTO_new();
        this->aesctx = CRYPTO::AES_CRYPTO_new();
    }

    ~NetworkNode()
    {
        delete[] this->keyDigest;
        delete[] this->keyHexDigest;
        delete[] this->id;

        this->keyDigest = 0;
        this->keyHexDigest = 0;
        this->id = 0;

        CRYPTO::RSA_CRYPTO_free(this->rsactx);
        CRYPTO::AES_CRYPTO_free(this->aesctx);
    }

    AES_CRYPTO getAES() { return this->aesctx; }

    RSA_CRYPTO getRSA() { return rsactx; }

    int aesctxDuplicate(const _AES_CRYPTO *aesctx)
    {
        return CRYPTO::AES_ctx_dup(this->aesctx, aesctx);
    }

    int pubkeyInit(const std::string &pubkeypem)
    {
        if (not pubkeypem.size())
        {
            return 0;
        }

        if (CRYPTO::RSA_init_key(pubkeypem, 0, 0, PUBLIC_KEY, this->rsactx) < 0)
        {
            return -1;
        }

        if (CRYPTO::RSA_init_ctx(this->rsactx, ENCRYPT) < 0)
        {
            return -1;
        }

        KEY_UTIL::getKeyDigest(pubkeypem, &this->keyDigest);
        CRYPTO::hex(this->keyDigest, 32, &this->keyHexDigest);

        return 0;
    }

    int aesctxInit(const BYTE *key = 0, SIZE keylen = 32)
    {
        if (key and keylen)
        {
            if (CRYPTO::AES_setup_key(key, keylen, this->aesctx) < 0)
            {
                return -1;
            }

            if (CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx) < 0)
            {
                return -1;
            }

            if (CRYPTO::AES_init_ctx(DECRYPT, this->aesctx) < 0)
            {
                return -1;
            }

            return 0;
        }
        else
        {
            BYTES keyBuffer = 0;
            int ret = 0;

            if (CRYPTO::rand_bytes(AES_GCM_KEY_SIZE, &keyBuffer) < 0)
            {
                ret = -1;
                goto cleanup;
            }

            if (CRYPTO::AES_setup_key(keyBuffer, AES_GCM_KEY_SIZE, this->aesctx) < 0)
            {
                ret = -1;
                goto cleanup;
            }

            if (CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx) < 0)
            {
                ret = -1;
                goto cleanup;
            }

            if (CRYPTO::AES_init_ctx(DECRYPT, this->aesctx) < 0)
            {
                ret = -1;
                goto cleanup;
            }

        cleanup:
            delete[] keyBuffer;
            keyBuffer = 0;

            return ret;
        }

        return 0;
    }

    const CHAR *encodeKey()
    {
        BYTES key = 0;
        CRYPTO::AES_read_key(this->aesctx, 32, &key);

        BASE64 base64key = 0;
        CRYPTO::base64_encode(key, 32, &base64key);

        delete[] key;

        return base64key;
    }

    const BYTE *getPubkeyDigest() const { return this->keyDigest; }

    const CHAR *getPubkeyHexDigest() const { return this->keyHexDigest; }

    void setPubkeyDigest(const BYTE *digest) { memcpy(this->keyDigest, digest, 32); }

    void setPubkeyHexDigest(const std::string &hexdigest) { strncpy(this->keyHexDigest, hexdigest.c_str(), 64); }

    int setId(const BYTE *id, SIZE idlen)
    {
        if (id)
        {
            memcpy(this->id, id, idlen);
            return 0;
        }

        return CRYPTO::rand_bytes(idlen, &this->id) < 0 ? -1 : 0;
    }

    int setSessionKey(const BYTE *sessionKey)
    {
        return CRYPTO::AES_setup_key(sessionKey, SESSION_KEY_SIZE, this->aesctx);
    }

    const CHAR *encodeId() const
    {
        BASE64 base64id = 0;
        CRYPTO::base64_encode(this->id, 16, &base64id);

        return base64id;
    }

    const BYTE *getId() const { return this->id; }

    const BYTE *getSessionKey()
    {
        BYTES sessionKey = 0;

        if (CRYPTO::AES_read_key(this->aesctx, SESSION_KEY_SIZE, &sessionKey) < 0)
        {
            delete[] sessionKey;
            sessionKey = 0;

            return 0;
        }

        return sessionKey;
    }

    void setPrevious(NetworkNode *previous) { this->previous = previous; }

    NetworkNode *getPrevious() { return this->previous; }

    void setNext(NetworkNode *next) { this->next = next; }

    NetworkNode *getNext() { return this->next; }
};

#endif
