#include "message_parser.hh"
#include "util.hh"
#include <string.h>
#include <cryptography/cryptography.hh>
#include "session.hh"

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

int MessageParser::decrypt(Route *r)
{
    this->remove_id();
    AES_CRYPTO ctx = r->get_aesctx();

    return this->decrypt(ctx);
}

int MessageParser::decrypt(SessionManager *session)
{
    this->remove_id();
    AES_CRYPTO ctx = session->get_ctx(this->get_parsed_id());

    return this->decrypt(ctx);
}

int MessageParser::handshake(RSA_CRYPTO rsactx, AES_CRYPTO aesctx)
{
    if (not this->is_handshake() or not CRYPTO::RSA_decrypt_ready(rsactx))
    {
        return -1;
    }

    this->remove_id();

    BYTES ptr = this->get_payload_ptr();
    SIZE payload_size = this->get_payload_size();

    BYTES key = 0;
    string pubkey_hexdigest;
    BYTES data = 0;

    int decrlen;

    int ret = 0;

    if ((decrlen = CRYPTO::RSA_decrypt(rsactx, ptr, MESSAGE_ENC_PUBKEY_SIZE, &key)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    ptr += 512;

    if (CRYPTO::AES_setup_key(key, decrlen, aesctx) < 0 or CRYPTO::AES_init(0, 0, 0, 0, aesctx) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    if ((decrlen = CRYPTO::AES_decrypt(aesctx, ptr, payload_size - MESSAGE_ENC_PUBKEY_SIZE, &data)) < 0)
    {
        ret = -1;
        goto endfunc;
    }

    data[decrlen] = 0;
    this->parse((const CHAR *)data);

    if (this->key_exists("pubkey"))
    {
        KEY_UTIL::get_key_hexdigest((*this)["pubkey"], pubkey_hexdigest);
        (*this)["address"] = pubkey_hexdigest;
    }

endfunc:

    delete[] key;
    delete[] data;

    return ret;
}

void MessageParser::remove_next()
{
    if(this->parsed_next_address_exists())
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
    if(this->parsed_id_exists())
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
