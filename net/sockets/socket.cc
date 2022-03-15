#include "socket.hh"

#include <netdb.h>

int Socket::createConnection(const std::string &host, const std::string &port)
{
    if (this->isConnected())
    {
        this->closeSocket();
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
        bytes_read = mp.update(this->extraBytesBuffer, this->getDelta());
        this->decreaseDelta(bytes_read);
    }

    return bytes_read;
}

ssize_t Socket::readNetworkData(MessageParser &mp)
{
    ssize_t bytes_read = this->readSocket(this->fd, SOCKET_MAX_BUFFER_SIZE);

    if (not bytes_read)
    {
        return 0;
    }

    if (bytes_read < 0)
    {
        // printErrorDetails();
        return -1;
    }

    SIZE parsed;

    if (not mp.getPayloadSize())
    {
        parsed = mp.update(this->extraBytesBuffer, bytes_read);
    }
    else
    {
        parsed = mp.appendPayload(this->extraBytesBuffer, bytes_read);
    }

    int currentDelta = bytes_read - parsed;

    this->increaseDelta(std::min(0, currentDelta));

    if (currentDelta)
    {
        this->rebaseData(parsed);
    }

    return parsed;
}

ssize_t Socket::readData(MessageParser &mp)
{
    // if more data read previously, read data from local buffer
    this->readLocalBuffer(mp);

    int ret;
    SIZE failedAttempts = 0;

    // then read socket until message in complete
    while (not mp.isComplete())
    {
        if ((ret = this->readNetworkData(mp)) < 0)
        {
            return -1;
        }
    
        not ret and failedAttempts ++;

        if (failedAttempts >= MAX_FAILED_READ_ATTEMPTS)
        {
            return -1;
        }
    }

    return mp.getPayloadSize();
}
