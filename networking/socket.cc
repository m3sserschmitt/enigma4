#include "socket.hh"
#include "../util/debug.hh"
#include <netdb.h>

int Socket::createConnection(const std::string &host, const std::string &port)
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
            close(s);
            continue;
        }

        if (connect(s, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }
    }

    if (not p)
    {
        return -1;
    }

    this->fd = s;

    return 0;
}

ssize_t Socket::writeData(const MessageBuilder &mb) const
{
    INFO("BYTES SENT: ", mb.getDatalen());
    return write(this->fd, mb.getData(), mb.getDatalen());
}

ssize_t Socket::writeData(const BYTE *data, SIZE datalen) const
{
    return write(this->fd, data, datalen);
}

ssize_t Socket::readLocalBuffer(MessageParser &mp)
{
    SIZE bytes_read = 0;

    if (this->getDelta() > 0)
    {
        bytes_read = mp.update(this->buffer, this->getDelta());
        this->decreaseDelta(bytes_read);
    }

    return bytes_read;
}

ssize_t Socket::readNetworkData(MessageParser &mp)
{
    // if more data read previously, then read data from local buffer
    this->readLocalBuffer(mp);

    while(not mp.isComplete())
    {
        //INFO("Reading data");
        if(this->readData(mp) < 0)
        {
            return -1;
        }
    }

    // INFO("message size: ", mp.get_datalen());

    return mp.getPayloadSize();
}
