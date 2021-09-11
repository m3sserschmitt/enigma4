#include "message.hh"

Message::~Message()
{
    delete[] this->data;
}

Message &Message::operator=(const Message &mb)
{
    if (this != &mb)
    {
        delete[] this->data;
        this->data = 0;

        this->data = new BYTE[MESSAGE_MAX_SIZE];
        this->update(mb.get_data(), mb.get_datalen());
    }

    return *this;
}