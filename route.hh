#ifndef ROUTE_HH
#define ROUTE_HH

#include <cryptography/cryptography.hh>
#include <cryptography/random.hh>
#include <string.h>
#include "util.hh"


class Route
{
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;
    BYTES keydigest;
    PLAINTEXT key_hexdigest;
    BYTES id;
    Route *next;
    Route *previous;

public:
    Route()
    {
        this->aesctx = CRYPTO::AES_CRYPTO_new();
        this->rsactx = CRYPTO::RSA_CRYPTO_new();

        CRYPTO::AES_iv_autoset(1, this->aesctx);
        CRYPTO::AES_iv_append(1, this->aesctx);

        this->next = 0;
        this->previous = 0;

        this->keydigest = new BYTE[32 + 1];
        this->key_hexdigest = new CHAR[64 + 1];
        this->id = new BYTE[16 + 1];

        memset(this->keydigest, 0, 32 + 1);
        memset(this->key_hexdigest, 0, 64 + 1);
        memset(this->id, 0, 16 + 1);
    }
    ~Route()
    {
        delete[] this->keydigest;
        delete[] this->key_hexdigest;
        delete[] this->id;

        this->keydigest = 0;
        this->key_hexdigest = 0;
        this->id = 0;
    }

    AES_CRYPTO get_aesctx() { return this->aesctx; }
    RSA_CRYPTO get_rsactx() { return this->rsactx; }

    int aesctx_dup(Route *route)
    {
        return CRYPTO::AES_ctx_dup(this->aesctx, route->aesctx);
    }
    int aesctx_dup(AES_CRYPTO ctx)
    {
        return CRYPTO::AES_ctx_dup(this->aesctx, ctx);
    }

    int rsactx_init(const std::string &pubkey)
    {
        if (CRYPTO::RSA_init_key(pubkey, 0, 0, PUBLIC_KEY, this->rsactx) < 0)
        {
            return -1;
        }

        KEY_UTIL::get_keydigest(pubkey, &this->keydigest);
        CRYPTO::hex(this->keydigest, 32, &this->key_hexdigest);

        return CRYPTO::RSA_init_ctx(this->rsactx, ENCRYPT);
    }
    int aesctx_init(const BYTE *key = 0, SIZE keylen = 32);

    const CHAR *encode_key() const
    {
        BYTES key = 0;
        CRYPTO::AES_read_key(this->aesctx, 32, &key);

        BASE64 base64key = 0;
        CRYPTO::base64_encode(key, 32, &base64key);

        delete[] key;

        return base64key;
    }

    const BYTE *get_keydigest() const { return this->keydigest; }
    const CHAR *get_key_hexdigest() const { return this->key_hexdigest; }

    int set_id(const BYTE *id)
    {
        if (id)
        {
            memcpy(this->id, id, 16);
            return 0;
        }

        return CRYPTO::rand_bytes(16, &this->id) < 0 ? -1 : 0;
    }

    const CHAR *encode_id() const
    {
        BASE64 base64id = 0;
        CRYPTO::base64_encode(this->id, 16, &base64id);

        return base64id;
    }
    const BYTE *get_id() { return this->id; }

    void set_previous(Route *previous) { this->previous = previous; }
    Route *get_previous() { return this->previous; }

    void set_next(Route *next) { this->next = next; }
    Route *get_next() { return this->next; }
};

#endif
