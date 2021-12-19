#ifndef _TYPES_HH
#define _TYPES_HH

#include "../libcryptography/include/cryptography.hh"

#include <string>

class CryptoContext
{
    AES_CRYPTO aesctx;
    RSA_CRYPTO rsactx;

    CryptoContext(const CryptoContext &);

    const CryptoContext &operator=(const CryptoContext &);

public:
    CryptoContext()
    {
        this->rsactx = CRYPTO::RSA_CRYPTO_new();
        this->aesctx = CRYPTO::AES_CRYPTO_new();

        //CRYPTO::AES_iv_autoset(1, this->aesctx);
        //CRYPTO::AES_iv_append(1, this->aesctx);
    }

    ~CryptoContext()
    {
        CRYPTO::RSA_CRYPTO_free(this->rsactx);
        CRYPTO::AES_CRYPTO_free(this->aesctx);
    }

    int rsaInitPubkey(const std::string &pubkeypem)
    {
        return CRYPTO::RSA_init_key(pubkeypem, 0, 0, PUBLIC_KEY, this->rsactx);
    }

    int rsaInitPubkeyFile(const std::string pubkeyfile)
    {
        return CRYPTO::RSA_init_key_file(pubkeyfile, 0, 0, PUBLIC_KEY, this->rsactx);
    }

    int rsaInitPrivkey(const std::string &privkeypem)
    {
        return CRYPTO::RSA_init_key(privkeypem, 0, 0, PRIVATE_KEY, this->rsactx);
    }

    int rsaInitPrivkeyFile(const std::string &privkeyfile)
    {
        return CRYPTO::RSA_init_key_file(privkeyfile, 0, 0, PRIVATE_KEY, this->rsactx);
    }

    int rsaInitEncryption()
    {
        return CRYPTO::RSA_init_ctx(this->rsactx, ENCRYPT);
    }

    int rsaInitDecryption()
    {
        return CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT);
    }

    int rsaInitSignature()
    {
        return CRYPTO::RSA_init_ctx(this->rsactx, SIGN);
    }

    int aesInit(const BYTE *key = 0, SIZE keylen = 16)
    {
        if (key and keylen)
        {
            if(CRYPTO::AES_setup_key(key, keylen, this->aesctx) < 0)
            {
                return -1;
            }

            if(CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx) < 0)
            {
                return -1;
            }

            if(CRYPTO::AES_init_ctx(DECRYPT, this->aesctx) < 0)
            {
                return -1;
            }

            return  0;
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

            if(CRYPTO::AES_setup_key(keyBuffer, AES_GCM_KEY_SIZE, this->aesctx) < 0)
            {
                ret = -1;
                goto cleanup;
            }

            if(CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx) < 0)
            {
                ret = -1;
                goto cleanup;
            }

            if(CRYPTO::AES_init_ctx(DECRYPT, this->aesctx) < 0)
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

    RSA_CRYPTO getRSA() { return this->rsactx; }

    AES_CRYPTO getAES() { return this->aesctx; }
};

#endif