#include "message_builder.hh"

using namespace std;

int MessageBuilder::encrypt(AES_CRYPTO ctx)
{
    if (not CRYPTO::AES_encrypt_ready(ctx))
    {
        return -1;
    }

    BYTES out = 0;
    int result = CRYPTO::AES_encrypt(ctx, this->get_data(), this->get_datalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->set_payload(out, result);
    if (not this->is_exit())
    {
        this->set_message_type(MESSAGE_ENC_AES);
    }

    delete[] out;
    return 0;
}

int MessageBuilder::handshake(AES_CRYPTO aesctx, RSA_CRYPTO rsactx, const string &pubkeypem)
{
    if (not CRYPTO::AES_encrypt_ready(aesctx) or not CRYPTO::RSA_encrypt_ready(rsactx))
    {
        return -1;
    }

    BYTES key = 0;
    BYTES encrkey = 0;
    BYTES encrdata = 0;
    int encrlen;

    string data = "pubkey: " + pubkeypem;

    int ret = 0;

    if (CRYPTO::AES_read_key(aesctx, 32, &key) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    if ((encrlen = CRYPTO::RSA_encrypt(rsactx, key, 32, &encrkey)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    this->set_payload(encrkey, encrlen);

    if (pubkeypem.size())
    {
        if ((encrlen = CRYPTO::AES_encrypt(aesctx, (const BYTE *)data.c_str(), data.size(), &encrdata)) < 0)
        {
            ret = -1;
            goto endfunc;
        }

        this->append_payload_end(encrdata, encrlen);
    }

    this->set_message_type(MESSAGE_HANDSHAKE);

endfunc:
    delete[] key;
    delete[] encrkey;
    delete[] encrdata;

    return ret;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    Message::operator=(mb);
    return *this;
}
