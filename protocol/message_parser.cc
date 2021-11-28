#include "../protocol/message_parser.hh"

#include "../onion_routing/connection.hh"

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
    if (not this->isExit() and this->getMessageType() != MESSAGE_ENC_AES)
    {
        return -1;
    }

    BYTES out = 0;
    int outlen = CRYPTO::AES_decrypt(ctx, this->getPayload(), this->getPayloadSize(), &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, outlen);

    delete[] out;
    return 0;
}

int MessageParser::decrypt(NetworkNode *route)
{
    this->removeId();
    AES_CRYPTO ctx = route->getAES();

    return this->decrypt(ctx);
}

int MessageParser::decrypt(Connection *conn)
{
    this->removeId();
    AES_CRYPTO ctx = conn->getEncryptionContext(this->getParsedId());

    return this->decrypt(ctx);
}

int MessageParser::handshakeDecryptSessionKey(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    BYTES key = 0;
    int decrlen;

    if ((decrlen = CRYPTO::RSA_decrypt(rsactx, this->getPayloadPtr() + 16, MESSAGE_ENC_PUBKEY_SIZE, &key)) < 0)
    {
        delete[] key;
        return -1;
    }

    if (CRYPTO::AES_setup_key(key, decrlen, aesctx) < 0 or CRYPTO::AES_init(0, 0, 0, 0, aesctx) < 0)
    {
        delete[] key;
        return -1;
    }

    delete[] key;
    return 0;
}

int MessageParser::handshakeDecryptPubkey(AES_CRYPTO aesctx, RSA_CRYPTO rsactx)
{
    BYTES pubkey = 0;
    SIZE encrlen = this->getPayloadSize() - 2 * MESSAGE_ENC_PUBKEY_SIZE - 16;
    int decrlen;

    if ((decrlen = CRYPTO::AES_decrypt(aesctx, this->getPayloadPtr()+ 16 + MESSAGE_ENC_PUBKEY_SIZE, encrlen, &pubkey)) < 0)
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

    // SIZE payload_size = this->get_payload_size();
    // this->set_payload_size(payload_size - MESSAGE_ENC_PUBKEY_SIZE);
    BYTES signature_ptr = this->getPayloadPtr() + this->getPayloadSize() - MESSAGE_ENC_PUBKEY_SIZE;
    SIZE datasize = this->getDatalen() - MESSAGE_ENC_PUBKEY_SIZE;

    bool authentic;
    if (CRYPTO::RSA_verify(ctx, signature_ptr, MESSAGE_ENC_PUBKEY_SIZE, this->getData(), datasize, authentic) < 0)
    {
        // this->set_payload_size(payload_size + MESSAGE_ENC_PUBKEY_SIZE);
        return -1;
    }

    // this->set_payload_size(payload_size + MESSAGE_ENC_PUBKEY_SIZE);

    return authentic ? 0 : -1;
}

int MessageParser::handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    if (not this->isHandshake())
    {
        return -1;
    }

    // this->remove_id();

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

    return 0;
}

void MessageParser::removeNext()
{
    if (this->parsedNextAddressExists())
    {
        return;
    }

    PLAINTEXT next = 0;
    CRYPTO::hex(this->getPayloadPtr(), MESSAGE_ADDRESS_SIZE, &next);

    this->parseddata["next"] = next;
    this->removePayloadBeg(MESSAGE_ADDRESS_SIZE);
    this->setPayloadSize(this->getPayloadSize() - MESSAGE_ADDRESS_SIZE);

    delete[] next;
}

void MessageParser::removeId()
{
    if (this->parsedIdExists())
    {
        return;
    }

    BASE64 id = new CHAR[128];
    CRYPTO::base64_encode(this->getPayloadPtr(), MESSAGE_ID_SIZE, &id);

    this->parseddata["id"] = id;
    this->removePayloadBeg(MESSAGE_ID_SIZE);
    this->setPayloadSize(this->getPayloadSize() - MESSAGE_ID_SIZE);

    delete[] id;
}

MessageParser &MessageParser::operator=(const MessageParser &mp)
{
    if (this != &mp)
    {
        this->parseddata = mp.parseddata;
    }

    Message::operator=(mp);

    return *this;
}

string &MessageParser::operator[](const string &key)
{
    return this->parseddata[toLowercase(key)];
}
