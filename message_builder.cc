#include "message_builder.hh"
#include "util.hh"

#include <string.h>
#include <random>

using namespace std;

MessageBuilder::MessageBuilder(const CHAR *data)
{
    this->data = new BYTE[this->message_max_size];
    memset(this->data, 0, this->message_max_size);

    this->datalen = strlen(data);
    memcpy(this->data, data, this->datalen);
    this->next_required = false;
}

MessageBuilder::MessageBuilder(const string &data)
{
    this->data = new BYTE[this->message_max_size];
    memset(this->data, 0, this->message_max_size);

    this->datalen = data.size();
    memcpy(this->data, data.c_str(), this->datalen);
    this->next_required = false;
}

MessageBuilder::MessageBuilder(const BYTE *data, SIZE datalen)
{
    this->data = new BYTE[this->message_max_size];
    memset(this->data, 0, this->message_max_size);

    this->datalen = datalen;
    memcpy(this->data, data, datalen);
    this->next_required = false;
}

MessageBuilder::MessageBuilder(const MessageBuilder &mb)
{
    this->data = new BYTE[this->message_max_size];
    memset(this->data, 0, this->message_max_size);

    this->datalen = mb.datalen;
    memcpy(this->data, mb.data, mb.datalen);
    this->next_required = mb.next_required;
}

/*
void MessageBuilder::gen_channel_id(PLAINTEXT *id)
{
    *id or (*id = new CHAR[16 + 1]);

    PLAINTEXT _id = *id;

    static random_device dev;
    static mt19937 rng(dev());

    uniform_int_distribution<int> dist(0, 15);

    const char *v = "0123456789abcdef";
    const bool dash[] = {0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0};

    for (int i = 0; i < 16; i++)
    {
        if (dash[i])
        {
            _id[i] = '-';
        }

        _id[i] = v[dist(rng)];
        _id[i] = v[dist(rng)];
    }
}
*/
void MessageBuilder::update(const BYTE *data, SIZE datalen)
{
    memset(this->data, 0, this->message_max_size);
    
    this->datalen = datalen;
    memcpy(this->data, data, datalen);
}

void MessageBuilder::update(const string &data)
{
    this->update(data.c_str());
}

void MessageBuilder::update(const CHAR *data)
{
    this->update((BYTES)data, strlen(data));
}

int MessageBuilder::set_iv(AES_CRYPTO ctx)
{
    memcpy(this->data + 16, this->data, this->datalen);

    if (CRYPTO::AES_read_iv(ctx, 16, &this->data) < 0)
    {
        return -1;
    }

    this->datalen += 16;

    return 0;
}

int MessageBuilder::encrypt(AES_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::AES_encrypt(ctx, this->data, this->datalen, &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, result);
    delete[] out;

    if (this->set_iv(ctx) < 0)
    {
        return -1;
    }

    return result;
}

int MessageBuilder::encrypt(RSA_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::RSA_encrypt(ctx, this->data, this->datalen, &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, result);
    delete[] out;

    return result;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    if (this != &mb)
    {
        delete this->data;
        this->data = new BYTE[this->message_max_size];

        this->datalen = mb.datalen;

        memcpy(this->data, mb.data, mb.datalen);
        this->next_required = mb.next_required;
    }

    return *this;
}
