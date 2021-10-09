#include "message_builder.hh"
#include "../onion_routing/route.hh"

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

int MessageBuilder::encrypt(Route *route)
{
    return this->encrypt(route->get_aesctx());
}

int MessageBuilder::handshake_setup_session_key(Route *route, bool add_all_keys)
{
    BYTES key = 0;
    BYTES encrkey = 0;
    int encrlen;

    int ret = 0;

    if (CRYPTO::AES_read_key(route->get_aesctx(), 32, &key) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    if ((encrlen = CRYPTO::RSA_encrypt(route->get_rsactx(), key, 32, &encrkey)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    this->append_payload_end(encrkey, encrlen);

endfunc:
    delete[] key;
    delete[] encrkey;

    return ret;
}

int MessageBuilder::handshake_setup_pubkey(AES_CRYPTO ctx, const string &pubkeypem)
{

    BYTES encrdata = 0;
    int encrlen;

    string data = "pubkey: " + pubkeypem;

    if ((encrlen = CRYPTO::AES_encrypt(ctx, (const BYTE *)data.c_str(), data.size(), &encrdata)) < 0)
    {
        delete[] encrdata;
        return -1;
    }

    this->append_payload_end(encrdata, encrlen);

    return 0;
}

int MessageBuilder::sign_message(RSA_CRYPTO ctx)
{
    BYTES signature = 0;
    int signlen;

    if ((signlen = CRYPTO::RSA_sign(ctx, this->get_data(), this->get_datalen(), &signature)) < 0)
    {
        delete[] signature;
        return -1;
    }

    this->append_payload_end(signature, signlen);

    delete[] signature;
    return 0;
}

int MessageBuilder::handshake(Route *route, RSA_CRYPTO signrsactx, const string &pubkeypem, bool add_all_keys)
{
    if (this->handshake_setup_session_key(route, add_all_keys) < 0)
    {
        return -1;
    }

    if (pubkeypem.size())
    {
        if (this->handshake_setup_pubkey(route->get_aesctx(), pubkeypem) < 0)
        {
            return -1;
        }

        if (this->sign_message(signrsactx) < 0)
        {
            return -1;
        }
    }

    this->set_message_type(MESSAGE_HANDSHAKE);

    return 0;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    Message::operator=(mb);
    return *this;
}
