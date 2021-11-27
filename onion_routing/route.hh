#ifndef ROUTE_HH
#define ROUTE_HH

#include "../libcryptography/include/cryptography.hh"

#include <string.h>
#include "../util/util.hh"

class NetworkNode
{
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;
    BYTES keyDigest;
    PLAINTEXT keyHexDigest;
    BYTES id;
    NetworkNode *next;
    NetworkNode *previous;

public:

    NetworkNode()
    {
        this->aesctx = CRYPTO::AES_CRYPTO_new();
        this->rsactx = CRYPTO::RSA_CRYPTO_new();

        CRYPTO::AES_iv_autoset(1, this->aesctx);
        CRYPTO::AES_iv_append(1, this->aesctx);

        this->next = 0;
        this->previous = 0;

        this->keyDigest = new BYTE[32 + 1];
        this->keyHexDigest = new CHAR[64 + 1];
        this->id = new BYTE[16 + 1];

        memset(this->keyDigest, 0, 32 + 1);
        memset(this->keyHexDigest, 0, 64 + 1);
        memset(this->id, 0, 16 + 1);
    }
    
    ~NetworkNode()
    {
        delete[] this->keyDigest;
        delete[] this->keyHexDigest;
        delete[] this->id;

        this->keyDigest = 0;
        this->keyHexDigest = 0;
        this->id = 0;
    }

    AES_CRYPTO getAesctx() { return this->aesctx; }
    
    RSA_CRYPTO getRsactx() { return this->rsactx; }

    int aesctxDuplicate(NetworkNode *route)
    {
        return CRYPTO::AES_ctx_dup(this->aesctx, route->aesctx);
    }
    
    int aesctxDuplicate(AES_CRYPTO ctx)
    {
        return CRYPTO::AES_ctx_dup(this->aesctx, ctx);
    }

    int rsactxInit(const std::string &pubkey)
    {
        if (CRYPTO::RSA_init_key(pubkey, 0, 0, PUBLIC_KEY, this->rsactx) < 0)
        {
            return -1;
        }

        KEY_UTIL::getKeyDigest(pubkey, &this->keyDigest);
        CRYPTO::hex(this->keyDigest, 32, &this->keyHexDigest);

        return CRYPTO::RSA_init_ctx(this->rsactx, ENCRYPT);
    }
    
    int aesctxInit(const BYTE *key = 0, SIZE keylen = 32);

    const CHAR *encodeKey() const
    {
        BYTES key = 0;
        CRYPTO::AES_read_key(this->aesctx, 32, &key);

        BASE64 base64key = 0;
        CRYPTO::base64_encode(key, 32, &base64key);

        delete[] key;

        return base64key;
    }

    const BYTE *getPubkeydigest() const { return this->keyDigest; }
    
    const CHAR *getPubkeyHexDigest() const { return this->keyHexDigest; }

    int setId(const BYTE *id)
    {
        if (id)
        {
            memcpy(this->id, id, 16);
            return 0;
        }

        return CRYPTO::rand_bytes(16, &this->id) < 0 ? -1 : 0;
    }

    const CHAR *encodeId() const
    {
        BASE64 base64id = 0;
        CRYPTO::base64_encode(this->id, 16, &base64id);

        return base64id;
    }
    
    const BYTE *getId() { return this->id; }

    void setPrevious(NetworkNode *previous) { this->previous = previous; }
    
    NetworkNode *getPrevious() { return this->previous; }

    void setNext(NetworkNode *next) { this->next = next; }
    
    NetworkNode *getNext() { return this->next; }
};

#endif
