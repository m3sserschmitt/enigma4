#include "message_builder.hh"
#include "util.hh"

using namespace std;

int MessageBuilder::encrypt(AES_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::AES_encrypt(ctx, this->get_data(), this->get_datalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->set_payload(out, result);
    this->set_enc_algorithm(MESSAGE_ENC_ALGORITHM_AES);

    delete[] out;

    return result;
}

int MessageBuilder::encrypt(RSA_CRYPTO ctx)
{
    BYTES out = 0;
    int result = CRYPTO::RSA_encrypt(ctx, this->get_data(), this->get_datalen(), &out);

    if (result < 0)
    {
        delete[] out;
        return -1;
    }

    this->set_payload(out, result);
    this->set_enc_algorithm(MESSAGE_ENC_ALGORITHM_RSA);

    delete[] out;

    return result;
}

MessageBuilder &MessageBuilder::operator=(const MessageBuilder &mb)
{
    Message::operator=(mb);
    return *this;
}
