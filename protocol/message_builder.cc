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
    BYTES keys = new BYTE[32 * 10];
    BYTES encrkeys = 0;
    int encrlen;

    int ret = 0;

    BYTES keys_ptr = keys;

    if (add_all_keys)
    {    
        for (Route *p = route; p; p = p->get_previous(), keys_ptr += 32)
        {
            if (CRYPTO::AES_read_key(route->get_aesctx(), 32, &keys_ptr) < 0)
            {
                ret = -1;
                goto endfunc;
            }
        }
    }
    else
    {
        if (CRYPTO::AES_read_key(route->get_aesctx(), 32, &keys_ptr) < 0)
        {
            ret = -1;
            goto endfunc;
        }
    }

    if ((encrlen = CRYPTO::RSA_encrypt(route->get_rsactx(), keys, (int)(keys_ptr - keys) + 32, &encrkeys)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    this->append_payload_end(route->get_id(), 16);
    this->append_payload_end(encrkeys, encrlen);

endfunc:
    delete[] keys;
    delete[] encrkeys;

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

    SIZE datasize = this->get_datalen();
    SIZE payload_size = this->get_payload_size();

    this->set_payload_size(payload_size + MESSAGE_ENC_PUBKEY_SIZE);

    if ((signlen = CRYPTO::RSA_sign(ctx, this->get_data(), datasize, &signature)) < 0)
    {
        delete[] signature;
        return -1;
    }

    this->set_payload_size(this->get_payload_size() - MESSAGE_ENC_PUBKEY_SIZE);
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

        this->set_message_type(MESSAGE_HANDSHAKE);

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
