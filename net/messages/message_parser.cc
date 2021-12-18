#include "message_parser.hh"

#include "../connection.hh"

using namespace std;

void MessageParser::parse(const CHAR *data)
{
    string _data = data;

    size_t p, n;

    string line;
    string key;
    string value;

    do
    {
        n = _data.find("\r\n");
        line = _data.substr(0, n);

        p = _data.find(':');

        if (p != string::npos)
        {
            key = strip(toLowercase(line.substr(0, p)), ' ');
            value = strip(line.substr(p + 1), ' ');

            this->parseddata[key] = value;
        }

        _data = _data.substr(n + 2);

    } while (n != string::npos);
}

int MessageParser::decrypt(AES_CRYPTO ctx)
{
    const int acceptedMessageTypes = MESSAGE_ENC_AES | MESSAGE_EXIT;

    if (not this->hasMessageType(acceptedMessageTypes))
    {
        return -1;
    }

    BYTES out = 0;
    int outlen = CRYPTO::AES_decrypt(ctx, this->getPayload() + SESSION_ID_SIZE, this->getPayloadSize() - SESSION_ID_SIZE, &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    this->parseNextAddress(out);
    this->reconstructNextMessage(out, outlen);

    delete[] out;
    out = 0;

    return 0;
}

int MessageParser::removeEncryptionLayer(NodesMap *nodes)
{
    this->parseSessionID();

    NetworkNode *node = nodes->operator[](getParsedId());

    if(not node)
    {
        return -1;
    }

    AES_CRYPTO ctx = node->getAES();

    if (not ctx)
    {
        return -1;
    }

    return this->decrypt(ctx);
}

int MessageParser::removeEncryptionLayer(Connection *conn)
{
    this->parseSessionID();

    AES_CRYPTO ctx = conn->getEncryptionContext(this->getParsedId());

    if (not ctx)
    {
        return -1;
    }

    return this->decrypt(ctx);
}

int MessageParser::handshakeDecryptSessionKey(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    BYTES decr = 0;
    BASE64 sessionID = new CHAR[ENCODED_SESSION_ID_SIZE + 1];

    int decrlen;

    int ret = 0;

    if ((decrlen = CRYPTO::RSA_decrypt(rsactx, this->getPayloadPtr(), MESSAGE_ENC_PUBKEY_SIZE, &decr)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    // first 16 bytes represent session ID;
    CRYPTO::base64_encode(decr, SESSION_ID_SIZE, &sessionID);
    this->parseddata.insert(pair<string, string>("id", sessionID));

    // last 32 bytes represent session key;
    if (CRYPTO::AES_setup_key(decr + SESSION_ID_SIZE, SESSION_KEY_SIZE, aesctx) < 0 or CRYPTO::AES_init(0, 0, 0, 0, aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

cleanup:
    delete[] decr;
    decr = 0;

    return ret;
}

int MessageParser::handshakeDecryptPubkey(AES_CRYPTO aesctx, RSA_CRYPTO rsactx)
{
    BYTES pubkey = 0;
    SIZE encrlen = this->getPayloadSize() - 2 * MESSAGE_ENC_PUBKEY_SIZE;
    int decrlen;

    if ((decrlen = CRYPTO::AES_decrypt(aesctx, this->getPayloadPtr() + MESSAGE_ENC_PUBKEY_SIZE, encrlen, &pubkey)) < 0)
    {
        delete[] pubkey;
        return -1;
    }

    pubkey[decrlen] = 0;
    this->parse((const CHAR *)pubkey);

    delete[] pubkey;
    string pubkey_hexdigest;

    if (this->parsedPubkeyExists())
    {
        const string &parsed_pubkey_pem = this->getParsedPubkey();

        CRYPTO::RSA_init_key(parsed_pubkey_pem, 0, 0, PUBLIC_KEY, rsactx);
        KEY_UTIL::getKeyHexDigest(this->getParsedPubkey(), pubkey_hexdigest);

        (*this)["address"] = pubkey_hexdigest;
    }

    return 0;
}

int MessageParser::messageVerifySignature(RSA_CRYPTO ctx)
{
    if (CRYPTO::RSA_init_ctx(ctx, VERIFY) < 0)
    {
        return -1;
    }

    BYTES signature_ptr = this->getPayloadPtr() + this->getPayloadSize() - MESSAGE_ENC_PUBKEY_SIZE;
    SIZE datasize = this->getDatalen() - MESSAGE_ENC_PUBKEY_SIZE;

    bool authentic;
    if (CRYPTO::RSA_verify(ctx, signature_ptr, MESSAGE_ENC_PUBKEY_SIZE, this->getData(), datasize, authentic) < 0)
    {
        return -1;
    }

    return authentic ? 0 : -1;
}

int MessageParser::handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    if (not this->isHandshake())
    {
        return -1;
    }

    if (this->handshakeDecryptSessionKey(rsactx, aesctx) < 0)
    {
        return -1;
    }

    if (this->getPayloadSize() > 2 * MESSAGE_ENC_PUBKEY_SIZE)
    {
        RSA_CRYPTO verify_ctx = CRYPTO::RSA_CRYPTO_new();

        if (this->handshakeDecryptPubkey(aesctx, verify_ctx) < 0)
        {
            return -1;
        }

        if (this->messageVerifySignature(verify_ctx) < 0)
        {
            return -1;
        }

        CRYPTO::RSA_CRYPTO_free(verify_ctx);
    }

    this->parseSessionID();

    return 0;
}
