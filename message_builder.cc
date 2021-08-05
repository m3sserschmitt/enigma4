#include "message_builder.hh"
#include "util.hh"

#include <string.h>

using namespace std;

MessageBuilder::MessageBuilder(const CHAR *data)
{
    this->data = new BYTE[this->message_max_size];
    SIZE datalen = strlen(data);
    this->offset = this->calculate_offset(datalen);

    memcpy(this->get_data_start(), data, datalen);
}

MessageBuilder::MessageBuilder(const string &data)
{
    this->data = new BYTE[this->message_max_size];
    this->offset = this->calculate_offset(data.size());

    memcpy(this->get_data_start(), data.c_str(), data.size());
}

MessageBuilder::MessageBuilder(const BYTE *data, SIZE datalen)
{
    this->data = new BYTE[this->message_max_size];
    this->offset = this->calculate_offset(datalen);

    memcpy(this->get_data_start(), data, datalen);
}

MessageBuilder::MessageBuilder(const MessageBuilder &mb)
{
    this->data = new BYTE[this->message_max_size];
    this->offset = mb.offset;

    memcpy(this->get_data_start(), mb.get_data_start(), mb.get_datalen());
}

void MessageBuilder::update(const BYTE *data, SIZE datalen)
{
    this->offset = MessageBuilder::calculate_offset(datalen);

    memcpy(this->get_data_start(), data, datalen);
}

void MessageBuilder::update(const string &data)
{
    this->update(data.c_str());
}

void MessageBuilder::update(const CHAR *data)
{
    this->update((BYTES)data, strlen(data));
}

void MessageBuilder::set_dest_address(const BYTE *address, SIZE addrlen)
{
    this->offset -= addrlen;

    memcpy(this->get_data_start(), address, addrlen);
}

void MessageBuilder::set_dest_address(RSA_CRYPTO ctx)
{
    BYTES address = 0;
    get_address(ctx, &address);

    this->set_dest_address(address, 32);
}   

int MessageBuilder::set_iv(AES_CRYPTO ctx)
{
    this->offset -= 16;
    BYTES p = this->get_data_start();

    if (CRYPTO::AES_read_iv(ctx, 16, &p) < 0)
    {
        return -1;
    }

    return 0;
}

int MessageBuilder::encrypt(AES_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::AES_encrypt(ctx, this->get_data_start(), this->get_datalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->update(out, result);
    delete[] out;

    if(this->set_iv(ctx) < 0)
    {
        return -1;
    }

    return result;
}

int MessageBuilder::encrypt(RSA_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::RSA_encrypt(ctx, this->get_data_start(), this->get_datalen(), &out);

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
        
        this->offset = mb.offset;

        memcpy(this->get_data_start(), mb.get_data_start(), mb.get_datalen());
    }

    return *this;
}
