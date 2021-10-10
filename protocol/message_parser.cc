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
            key = strip(to_lowercase(line.substr(0, p)), ' ');
            value = strip(line.substr(p + 1), ' ');

            this->parseddata[key] = value;
        }

        _data = _data.substr(n + 2);

    } while (n != string::npos);
}

int MessageParser::decrypt(AES_CRYPTO ctx)
{
    if (not this->is_exit() and this->get_message_type() != MESSAGE_ENC_AES)
    {
        return -1;
    }

    BYTES out = 0;
    int outlen = CRYPTO::AES_decrypt(ctx, this->get_payload(), this->get_payload_size(), &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, outlen);

    delete[] out;
    return 0;
}

int MessageParser::decrypt(Route *route)
{
    this->remove_id();
    AES_CRYPTO ctx = route->get_aesctx();

    return this->decrypt(ctx);
}

int MessageParser::decrypt(Connection *conn)
{
    this->remove_id();
    AES_CRYPTO ctx = conn->sessions->get_ctx(this->get_parsed_id());

    return this->decrypt(ctx);
}

int MessageParser::handshake_decrypt_session_key(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    BYTES key = 0;
    int decrlen;

    if ((decrlen = CRYPTO::RSA_decrypt(rsactx, this->get_payload_ptr() + 16, MESSAGE_ENC_PUBKEY_SIZE, &key)) < 0)
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

int MessageParser::handshake_decrypt_pubkey(AES_CRYPTO aesctx, RSA_CRYPTO rsactx)
{
    BYTES pubkey = 0;
    SIZE encrlen = this->get_payload_size() - 2 * MESSAGE_ENC_PUBKEY_SIZE - 16;
    int decrlen;

    if ((decrlen = CRYPTO::AES_decrypt(aesctx, this->get_payload_ptr()+ 16 + MESSAGE_ENC_PUBKEY_SIZE, encrlen, &pubkey)) < 0)
    {
        delete[] pubkey;
        return -1;
    }

    pubkey[decrlen] = 0;
    this->parse((const CHAR *)pubkey);

    delete[] pubkey;
    string pubkey_hexdigest;

    if (this->parsed_pubkey_exists())
    {
        const string &parsed_pubkey_pem = this->get_parsed_pubkey();

        CRYPTO::RSA_init_key(parsed_pubkey_pem, 0, 0, PUBLIC_KEY, rsactx);
        KEY_UTIL::get_key_hexdigest(this->get_parsed_pubkey(), pubkey_hexdigest);

        (*this)["address"] = pubkey_hexdigest;
    }

    return 0;
}

int MessageParser::message_verify_signature(RSA_CRYPTO ctx)
{
    if (CRYPTO::RSA_init_ctx(ctx, VERIFY) < 0)
    {
        return -1;
    }

    // SIZE payload_size = this->get_payload_size();
    // this->set_payload_size(payload_size - MESSAGE_ENC_PUBKEY_SIZE);
    BYTES signature_ptr = this->get_payload_ptr() + this->get_payload_size() - MESSAGE_ENC_PUBKEY_SIZE;
    SIZE datasize = this->get_datalen() - MESSAGE_ENC_PUBKEY_SIZE;

    bool authentic;
    if (CRYPTO::RSA_verify(ctx, signature_ptr, MESSAGE_ENC_PUBKEY_SIZE, this->get_data(), datasize, authentic) < 0)
    {
        // this->set_payload_size(payload_size + MESSAGE_ENC_PUBKEY_SIZE);
        return -1;
    }

    // this->set_payload_size(payload_size + MESSAGE_ENC_PUBKEY_SIZE);

    return authentic ? 0 : -1;
}

int MessageParser::handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    if (not this->is_handshake())
    {
        return -1;
    }

    // this->remove_id();

    if (this->handshake_decrypt_session_key(rsactx, aesctx) < 0)
    {
        return -1;
    }

    if (this->get_payload_size() > 2 * MESSAGE_ENC_PUBKEY_SIZE)
    {
        RSA_CRYPTO verify_ctx = CRYPTO::RSA_CRYPTO_new();

        if (this->handshake_decrypt_pubkey(aesctx, verify_ctx) < 0)
        {
            return -1;
        }

        if (this->message_verify_signature(verify_ctx) < 0)
        {
            return -1;
        }

        CRYPTO::RSA_CRYPTO_free(verify_ctx);
    }

    return 0;
}

void MessageParser::remove_next()
{
    if (this->parsed_next_address_exists())
    {
        return;
    }

    PLAINTEXT next = 0;
    CRYPTO::hex(this->get_payload_ptr(), MESSAGE_ADDRESS_SIZE, &next);

    this->parseddata["next"] = next;
    this->remove_payload_beg(MESSAGE_ADDRESS_SIZE);
    this->set_payload_size(this->get_payload_size() - MESSAGE_ADDRESS_SIZE);

    delete[] next;
}

void MessageParser::remove_id()
{
    if (this->parsed_id_exists())
    {
        return;
    }

    BASE64 id = new CHAR[128];
    CRYPTO::base64_encode(this->get_payload_ptr(), MESSAGE_ID_SIZE, &id);

    this->parseddata["id"] = id;
    this->remove_payload_beg(MESSAGE_ID_SIZE);
    this->set_payload_size(this->get_payload_size() - MESSAGE_ID_SIZE);

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
    return this->parseddata[to_lowercase(key)];
}
