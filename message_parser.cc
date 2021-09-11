#include "message_parser.hh"
#include "util.hh"
#include <string.h>
#include <cryptography/cryptography.hh>

using namespace std;

void MessageParser::parse()
{
    string data = (PLAINTEXT)this->get_payload();

    size_t p, n;

    string line;
    string key;
    string value;

    do
    {
        n = data.find("\r\n");
        line = data.substr(0, n);

        p = data.find(':');

        if (p != string::npos)
        {
            key = strip(to_lowercase(line.substr(0, p)), ' ');
            value = strip(line.substr(p + 1), ' ');

            this->parseddata[key] = value;
        }

        data = data.substr(n + 2);

    } while (n != string::npos);
}

int MessageParser::decrypt(AES_CRYPTO ctx)
{
    if(this->get_enc_algorithm() != MESSAGE_ENC_ALGORITHM_AES)
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
    return outlen;
}

int MessageParser::decrypt(RSA_CRYPTO ctx)
{
    if(this->get_enc_algorithm() != MESSAGE_ENC_ALGORITHM_RSA)
    {
        return -1;
    }

    BYTES out = 0;
    int outlen = CRYPTO::RSA_decrypt(ctx, this->get_payload(), this->get_payload_size(), &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, outlen);

    return outlen;
}

void MessageParser::remove_next()
{
    PLAINTEXT next = 0;
    CRYPTO::hex(this->get_payload_ptr(), MESSAGE_ADDRESS_SIZE, &next);

    this->parseddata["next"] = next;
    this->remove_payload_beg(MESSAGE_ADDRESS_SIZE);
    this->set_payload_size(this->get_payload_size() - MESSAGE_ADDRESS_SIZE);

    delete[] next;
}

void MessageParser::remove_id()
{
    BASE64 id = 0;
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
