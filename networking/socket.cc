#include "socket.hh"

#include <netdb.h>

int Socket::create_connection(const std::string &host, const std::string &port)
{
    if (this->fd > 0)
    {
        return -1;
    }

    int s;

    addrinfo addr_info;
    addr_info.ai_family = AF_INET;
    addr_info.ai_socktype = SOCK_STREAM;
    addr_info.ai_protocol = 0;
    addr_info.ai_flags = 0;

    addrinfo *res;
    addrinfo *p;

    if (getaddrinfo(host.c_str(), port.c_str(), &addr_info, &res) != 0)
    {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((s = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        {
            continue;
        }

        if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }

        close(s);
    }

    if (not p)
    {
        return -1;
    }

    this->fd = s;

    return 0;
}

ssize_t Socket::write_data(const MessageBuilder &mb) const
{
    return write(this->fd, mb.get_data(), mb.get_datalen());
}

ssize_t Socket::write_data(const BYTE *data, SIZE datalen) const
{
    return write(this->fd, data, datalen);
}

ssize_t Socket::read_buffer(MessageParser &mp)
{
    SIZE buffread = 0;
    if (this->delta > 0)
    {
        buffread = mp.update(this->buffer, this->delta);
        this->delta -= buffread;
    }

    return buffread;
}

ssize_t Socket::read_data(MessageParser &mp)
{
    ssize_t inlen;
    SIZE parsed = this->read_buffer(mp);

    if (parsed and mp.is_complete())
    {
        return parsed;
    }

    while ((inlen = this->read_data()) > 0)
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
