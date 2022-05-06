#include "message/message_parser.hh"

#include "connection/connection.hh"

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

    if (not this->hasAtLeastOneType(acceptedMessageTypes))
    {
        return -1;
    }

    BYTES out = 0;
    int outlen = CRYPTO::AES_auth_decrypt(ctx, this->getPayload() + SESSION_ID_SIZE, this->getPayloadSize() - SESSION_ID_SIZE, &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    this->parseNextAddress(out + MESSAGE_PAYLOAD_OFFSET);
    this->reconstructNextMessage(out, outlen);

    delete[] out;
    out = 0;

    return 0;
}

int MessageParser::removeEncryptionLayer(std::map<std::string, NetworkNode *> *nodes)
{
    this->parseSessionID();

    NetworkNode *node = nodes->operator[](getParsedId());

    if (not node)
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

int MessageParser::handshakePhaseOneRequest(RSA_CRYPTO rsadecrctx, AES_CRYPTO ctx, std::string &pubkeypem) const
{
    int ret = 0;

    BYTES decrkey = 0;
    int decrkeylen;

    BYTES decrpubkey = 0;

    BYTES encrkeyptr = this->getPayloadPtr();

    if ((decrkeylen = CRYPTO::RSA_decrypt(rsadecrctx, encrkeyptr, MESSAGE_ENC_PUBKEY_SIZE, &decrkey)) < 0 || decrkeylen != SESSION_KEY_SIZE)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_setup_key(decrkey, decrkeylen, ctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_init_ctx(DECRYPT, ctx) < 0 || CRYPTO::AES_init_ctx(ENCRYPT, ctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if ((decrkeylen = CRYPTO::AES_auth_decrypt(ctx, encrkeyptr + MESSAGE_ENC_PUBKEY_SIZE, this->getPayloadSize() - MESSAGE_ENC_PUBKEY_SIZE, &decrpubkey)) < 0)
    {
        ret = -1;
        goto cleanup;
    }
    
    decrpubkey[decrkeylen] = 0;
    pubkeypem = (PLAINTEXT)decrpubkey;

cleanup:
    delete[] decrpubkey;
    decrpubkey = 0;

    delete[] decrkey;
    decrkey = 0;

    return ret;
}

int MessageParser::handshakePhaseOneResponse(AES_CRYPTO aesctx, BYTES *sessionId, BYTES *test) const
{
    if (not this->hasType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_ENC_AES))
    {
        return -1;
    }

    *sessionId or (*sessionId = new BYTE[SESSION_ID_SIZE + 1]);
    *test or (*test = new BYTE[HANDSHAKE_TEST_PHRASE_SIZE + 1]);

    if (not *sessionId or not *test)
    {
        return -1;
    }

    int ret = 0;

    BYTES data = 0;
    int datalen;

    if (CRYPTO::AES_auth_decrypt(aesctx, this->getPayloadPtr(), this->getPayloadSize(), &data) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    memcpy(*sessionId, data, SESSION_ID_SIZE);
    memcpy(*test, data + SESSION_ID_SIZE, HANDSHAKE_TEST_PHRASE_SIZE);

cleanup:
    delete[] data;
    data = 0;

    return ret;
}

int MessageParser::handshakePhaseTwoRequest(RSA_CRYPTO rsaverifctx, const BYTE *sessionId, const BYTE *test) const
{
    if (not sessionId or not test)
    {
        return -1;
    }

    BYTES payloadptr = this->getPayloadPtr();

    if (memcmp(sessionId, payloadptr, SESSION_ID_SIZE) != 0)
    {
        return -1;
    }

    bool authentic;
    if (CRYPTO::RSA_verify(rsaverifctx, payloadptr + SESSION_ID_SIZE, MESSAGE_ENC_PUBKEY_SIZE, test, HANDSHAKE_TEST_PHRASE_SIZE, authentic) < 0 or not authentic)
    {
        return -1;
    }

    return 0;
}

int MessageParser::addSessionMessage(RSA_CRYPTO decrctx, BYTES *sessionId, BYTES *sessionKey)
{
    if (not this->hasType(MESSAGE_ADD_SESSION | MESSAGE_ENC_RSA))
    {
        return -1;
    }

    *sessionId or (*sessionId = new BYTE[SESSION_ID_SIZE + 1]);
    *sessionKey or (*sessionKey = new BYTE[SESSION_KEY_SIZE + 1]);

    if(not *sessionId or not *sessionKey)
    {
        return -1;
    }

    int ret = 0;

    BYTES decrdata = 0;
    int decrlen;

    if ((decrlen = CRYPTO::RSA_decrypt(decrctx, this->getPayloadPtr(), MESSAGE_ENC_PUBKEY_SIZE, &decrdata)) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    memcpy(*sessionId, decrdata, SESSION_ID_SIZE);
    memcpy(*sessionKey, decrdata + SESSION_ID_SIZE, SESSION_KEY_SIZE);

    this->parseSessionId(*sessionId);

cleanup:
    delete[] decrdata;

    decrdata = 0;

    return ret;
}
