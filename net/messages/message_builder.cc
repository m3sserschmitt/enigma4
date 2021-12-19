#include "message_builder.hh"

#include "../network_node.hh"

#include "../../util/debug.hh"

using namespace std;

int MessageBuilder::encrypt(AES_CRYPTO ctx)
{
    if (not CRYPTO::AES_encrypt_ready(ctx))
    {
        return -1;
    }

    BYTES out = 0;
    int result = CRYPTO::AES_auth_encrypt(ctx, this->getData(), this->getDatalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->setPayload(out, result);
    this->addIfPressentOrOverrideMessageType(MESSAGE_EXIT, MESSAGE_ENC_AES);

    delete[] out;
    return 0;
}

int MessageBuilder::encrypt(NetworkNode *route)
{
    return this->encrypt(route->getAES());
}

int MessageBuilder::handshakeSetupSessionKey(NetworkNode *route)
{
    BYTES sessionIdAndKey = new BYTE[SESSION_ID_SIZE + SESSION_KEY_SIZE + 1];
    BYTES ptr = sessionIdAndKey;

    BYTES encr = 0;
    int encrlen;

    int ret = 0;

    // first 16 bytes represent session ID;
    memcpy(ptr, route->getId(), SESSION_ID_SIZE);
    ptr += SESSION_ID_SIZE;

    // last 32 bytes represent session key;
    if (CRYPTO::AES_read_key(route->getAES(), SESSION_KEY_SIZE, &ptr) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if ((encrlen = CRYPTO::RSA_encrypt(route->getRSA(), sessionIdAndKey, SESSION_KEY_SIZE + SESSION_ID_SIZE, &encr)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->appendPayloadEnd(encr, encrlen);

cleanup:
    delete[] sessionIdAndKey;
    delete[] encr;

    sessionIdAndKey = 0;
    encr = 0;

    return ret;
}

int MessageBuilder::handshakeSetupPubkey(AES_CRYPTO ctx, const string &pubkeypem)
{
    BYTES encrdata = 0;
    int encrlen;

    string data = "pubkey: " + pubkeypem;

    if ((encrlen = CRYPTO::AES_auth_encrypt(ctx, (const BYTE *)data.c_str(), data.size(), &encrdata)) < 0)
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
