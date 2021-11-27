#include "route.hh"

int NetworkNode::aesctxInit(const BYTE *key, SIZE keylen)
{
    if (key and keylen)
    {
        return CRYPTO::AES_setup_key(key, keylen, this->aesctx);
    }
    else
    {
        BYTES _key = 0;
        BYTES _salt = 0;
        int ret = 0;

        if (CRYPTO::rand_bytes(32, &_key) < 0)
        {
            ret = -1;
            goto __end;
        }

        if (CRYPTO::rand_bytes(32, &_salt) < 0)
        {
            ret = -1;
            goto __end;
        }

        if (CRYPTO::AES_init(_key, 32, _salt, 100000, this->aesctx) < 0)
        {
            ret = -1;
            goto __end;
        }

    __end:
        delete[] _key;
        delete[] _salt;

        return ret;
    }
}