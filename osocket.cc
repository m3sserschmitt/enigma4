#include "osocket.hh"
#include <unistd.h>
#include <math.h>

ssize_t OSocket::write_data(const MessageBuilder &mb) const
{
    return write(this->fd, mb.get_data(), mb.get_datalen());
}

ssize_t OSocket::write_data(const BYTE *data, SIZE datalen) const
{
    return write(this->fd, data, datalen);
}

ssize_t OSocket::read_data(MessageParser &mp)
{
    ssize_t dataread;
    SIZE required = O_SOCKET_MAX_BUFFER_SIZE;

    while ((dataread = read(this->fd, this->buffer + (this->delta > 0 ? this->delta : 0), required)) > 0)
    {
        if (this->delta < 0) // not enough data read previously
        {
            mp.append_payload(this->buffer, dataread);
        }
        else
        {
            mp.update(this->buffer, dataread);
        }

        this->delta = mp.get_actual_payload_size() - mp.get_payload_size();

        if (this->delta >= 0) // more data than required
        {
            memcpy(this->buffer, this->buffer + dataread - delta, this->delta);
            break;
        }
        else
        {
            required = this->delta;
            continue;
        }
    }

    return dataread;
}
