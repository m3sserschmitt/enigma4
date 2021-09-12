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

ssize_t OSocket::read_buffer(MessageParser &mp)
{
    SIZE buffread = 0;
    if (this->delta > 0)
    {
        buffread = mp.update(this->buffer, this->delta);
        this->delta -= buffread;
    }

    return buffread;
}

ssize_t OSocket::read_data(MessageParser &mp)
{
    ssize_t inlen;
    SIZE parsed = this->read_buffer(mp);

    if (parsed and mp.is_complete())
    {
        return parsed;
    }

    while ((inlen = read(this->fd, this->buffer + (this->delta > 0 ? this->delta : 0), O_SOCKET_MAX_BUFFER_SIZE)) > 0)
    {
        if (this->delta < 0) // if not enough data read previously
        {
            // append to payload in order to complete message;
            parsed = mp.append_payload(this->buffer, inlen);
            this->delta += inlen;
        }
        else
        {
            parsed = mp.update(this->buffer, inlen);
            this->delta = -1 * mp.get_required_size();

            if (not this->delta)
            {
                this->delta = inlen - parsed;
            }
        }

        if (delta > 0)
        {
            memcpy(this->buffer, this->buffer + parsed, this->delta);
        }

        if (mp.is_complete())
        {
            break;
        }
    }

    return inlen < 0 ? -1 : parsed;
}
