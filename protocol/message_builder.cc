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
    int result = CRYPTO::AES_encrypt(ctx, this->getData(), this->getDatalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->setPayload(out, result);
    if (not this->isExit())
    {
        this->setMessageType(MESSAGE_ENC_AES);
    }

    delete[] out;
    return 0;
}

int MessageBuilder::encrypt(NetworkNode *route)
{
    return this->encrypt(route->getAES());
}

int MessageBuilder::handshakeSetupSessionKey(NetworkNode *route)
{
    BYTES keys = new BYTE[32 * 10];
    BYTES encrkeys = 0;
    int encrlen;

    int ret = 0;

    BYTES keys_ptr = keys;

    // if (add_all_keys)
    // {    
    //     for (NetworkNode *p = route; p; p = p->getPrevious(), keys_ptr += 32)
    //     {
    //         if (CRYPTO::AES_read_key(route->getAesctx(), 32, &keys_ptr) < 0)
    //         {
    //             ret = -1;
    //             goto endfunc;
    //         }
    //     }
    // }
    // else
    //{
        if (CRYPTO::AES_read_key(route->getAES(), 32, &keys_ptr) < 0)
        {
            ret = -1;
            goto endfunc;
        }
    //}

    if ((encrlen = CRYPTO::RSA_encrypt(route->getRSA(), keys, (int)(keys_ptr - keys) + 32, &encrkeys)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    this->appendPayloadEnd(route->getId(), 16);
    this->appendPayloadEnd(encrkeys, encrlen);

endfunc:
    delete[] keys;
    delete[] encrkeys;

    return ret;
}

int MessageBuilder::handshakeSetupPubkey(AES_CRYPTO ctx, const string &pubkeypem)
{
    BYTES encrdata = 0;
    int encrlen;

    string data = "pubkey: " + pubkeypem;

    if ((encrlen = CRYPTO::AES_encrypt(ctx, (const BYTE *)data.c_str(), data.size(), &encrdata)) < 0)
    {
        delete[] encrdata;
        return -1;
    }

    this->appendPayloadEnd(encrdata, encrlen);

    return 0;
}

int MessageBuilder::signMessage(RSA_CRYPTO ctx)
{
    BYTES signature = 0;
    int signlen;

    SIZE current_datalen = this->getDatalen();
    this->increasePayloadSize(MESSAGE_ENC_PUBKEY_SIZE);

    if ((signlen = CRYPTO::RSA_sign(ctx, this->getData(), current_datalen, &signature)) < 0)
    {
        delete[] signature;
        return -1;
    }

    this->decreasePayloadSize(MESSAGE_ENC_PUBKEY_SIZE);
    this->appendPayloadEnd(signature, signlen);

    delete[] signature;
    return 0;
}

int MessageBuilder::handshake(NetworkNode *route, RSA_CRYPTO signrsactx, const string &pubkeypem)
{
    if (this->handshakeSetupSessionKey(route) < 0)
    {
        return -1;
    }

    if (pubkeypem.size())
    {
        if (this->handshakeSetupPubkey(route->getAES(), pubkeypem) < 0)
        {
            return -1;
        }

        this->setMessageType(MESSAGE_HANDSHAKE);

        if (this->signMessage(signrsactx) < 0)
        {
            return -1;
        }
    }

    this->setMessageType(MESSAGE_HANDSHAKE);

    return 0;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    Message::operator=(mb);
    return *this;
}
