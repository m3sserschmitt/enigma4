#include "message_builder.hh"

#include "../network_node.hh"

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

int MessageBuilder::handshakePhaseOneRequest(const BYTE *sessionKey, const std::string &pubkeypem, RSA_CRYPTO rsaencrctx, AES_CRYPTO ctx)
{
    int ret = 0;

    BYTES encrkey = 0;
    int encrkeylen;

    BYTES encrpubkey = 0;
    int encrpubkeylen = 0;

    if ((encrkeylen = CRYPTO::RSA_encrypt(rsaencrctx, sessionKey, SESSION_KEY_SIZE, &encrkey)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if((encrpubkeylen = CRYPTO::AES_auth_encrypt(ctx, (const BYTE *)pubkeypem.c_str(), pubkeypem.size(), &encrpubkey)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->appendPayloadEnd(encrkey, encrkeylen);
    this->appendPayloadEnd(encrpubkey, encrpubkeylen);

    this->setMessageType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_ENC_RSA | MESSAGE_ENC_AES);

cleanup:
    delete[] encrkey;
    encrkey = 0;

    delete[] encrpubkey;
    encrpubkey = 0;

    return ret;
}

int MessageBuilder::handshakePhaseTwoRequest(const BYTE *sessionId, const BYTE *test, RSA_CRYPTO signctx)
{
    int ret = 0;

    BYTES signature = 0;
    int signlen;

    if((signlen = CRYPTO::RSA_sign(signctx, test, HANDSHAKE_TEST_PHRASE_SIZE, &signature)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->appendPayloadEnd(sessionId, SESSION_ID_SIZE);
    this->appendPayloadEnd(signature, signlen);

    this->setMessageType(MESSAGE_HANDSHAKE_PHASE_TWO | MESSAGE_ENC_RSA);
    
cleanup:
    delete[] signature;
    signature = 0;

    return ret;
}

int MessageBuilder::handshakePhaseOneResponse(const BYTE *sessionId, const BYTE *test, AES_CRYPTO aesctx)
{
    int ret = 0;

    int datalen = SESSION_ID_SIZE + HANDSHAKE_TEST_PHRASE_SIZE;
    BYTES data = new BYTE[datalen + 1];

    BYTES encrdata = 0;
    int encrdatalen;

    memcpy(data, sessionId, SESSION_ID_SIZE);
    memcpy(data + SESSION_ID_SIZE, test, HANDSHAKE_TEST_PHRASE_SIZE);

    if((encrdatalen = CRYPTO::AES_auth_encrypt(aesctx, data, datalen, &encrdata)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->appendPayloadEnd(encrdata, encrdatalen);

    this->setMessageType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_ENC_AES);

cleanup:
    delete[] data;
    delete[] encrdata;

    data = 0;
    encrdata = 0;

    return ret;
}

int MessageBuilder::addSessionMessage(const BYTE *sessionId, const BYTE *sessionKey, RSA_CRYPTO rsaencrctx)
{
    if(not sessionId or not sessionKey)
    {
        return -1;
    }

    BYTES data = new BYTE[SESSION_ID_SIZE + SESSION_KEY_SIZE + 1];

    if(not data)
    {
        return -1;
    }

    memcpy(data, sessionId, SESSION_ID_SIZE);
    memcpy(data + SESSION_ID_SIZE, sessionKey, SESSION_KEY_SIZE);

    int ret = 0;

    BYTES encrdata = 0;
    int encrlen;

    if((encrlen = CRYPTO::RSA_encrypt(rsaencrctx, data, SESSION_ID_SIZE + SESSION_KEY_SIZE, &encrdata)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->appendPayloadEnd(encrdata, encrlen);

    this->setMessageType(MESSAGE_ADD_SESSION | MESSAGE_ENC_RSA);

cleanup:
    delete[] encrdata;
    encrdata = 0;

    return ret;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    Message::operator=(mb);
    return *this;
}
