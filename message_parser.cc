#include "message_parser.hh"
#include "util.hh"
#include <string.h>
#include <cryptography/cryptography.hh>

using namespace std;

MessageParser::MessageParser(const MessageParser &mp) : data(mp.data), datalen(mp.datalen)
{
    this->rawdata = new BYTE[this->max_message_size];

    memset(this->rawdata, 0, this->max_message_size);
    memcpy(this->rawdata, mp.rawdata, mp.datalen);
}

void MessageParser::parse()
{
    string data = (PLAINTEXT)this->rawdata;

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

            this->data[key] = value;
        }

        data = data.substr(n + 2);

    } while (n != string::npos);
}

void MessageParser::update(const BYTE *data, SIZE datalen)
{
    memset(this->rawdata, 0, this->max_message_size);
    memcpy(this->rawdata, data, datalen);
    this->datalen = datalen;
}

int MessageParser::decrypt(AES_CRYPTO ctx)
{
    // get iv;
    CRYPTO::AES_setup_iv(this->rawdata, 16, ctx);

    // decrypt;
    BYTES out = 0;
    int outlen = CRYPTO::AES_decrypt(ctx, this->rawdata + 16, this->datalen - 16, &out);

    if (outlen < 0)
    {
        delete[] out;
        return -1;
    }

    // update with decrypted data and get next address;
    // PLAINTEXT addr = 0;
    // CRYPTO::hex(out, 32, &addr);
    // this->data.insert(pair<string, string>("next", addr));
    // delete[] addr;

    // this->update(out + 32, outlen - 32);

    this->update(out, outlen);

    delete[] out;
    return outlen;
}

int MessageParser::decrypt(RSA_CRYPTO ctx)
{
    BYTES out = 0;
    int outlen = CRYPTO::RSA_decrypt(ctx, this->rawdata, this->datalen, &out);

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
    CRYPTO::hex(this->rawdata, 32, &next);

    this->data["next"] = next;
    delete[] next;

    shift_left(32);
}

void MessageParser::remove_id()
{
    BASE64 id = 0;
    CRYPTO::base64_encode(this->rawdata, 16, &id);

    this->data["id"] = id;
    delete[] id;

    shift_left(16);
}

MessageParser &MessageParser::operator=(const MessageParser &mp)
{
    if (this != &mp)
    {
        // copy parsed data;
        this->data = mp.data;

        // allocate new memory buffer for rawdata, and copy from mp;
        if (this->rawdata)
        {
            delete this->rawdata;
            this->rawdata = 0;

            this->rawdata = new BYTE[this->max_message_size];
            memcpy(this->rawdata, mp.rawdata, mp.datalen);
        }

        this->datalen = mp.datalen;
    }

    return *this;
}

string &MessageParser::operator[](const string &key)
{
    return this->data[to_lowercase(key)];
}
