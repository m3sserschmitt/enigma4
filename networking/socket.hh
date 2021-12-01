#ifndef SOCKET_HH
#define SOCKET_HH

#include "../protocol/message_parser.hh"
#include "../protocol/message_builder.hh"
#include "../util/debug.hh"

#include <math.h>
#include <unistd.h>

class Socket
{
    static const SIZE SOCKET_MAX_BUFFER_SIZE = 512;
    static const SIZE MAX_FAILED_READ_ATTEMPTS = 128;

    int fd;
    BYTES buffer;
    int delta;

    ssize_t readLocalBuffer(MessageParser &mp);

    virtual ssize_t readNetworkData(MessageParser &mp);

    Socket(const Socket &);

    const Socket &operator=(const Socket &s);

protected:
    BYTES getBuffer() { return this->buffer; };

    void setDelta(int delta) { this->delta = delta; }

    int getDelta() { return this->delta; }

    void increaseDelta(SIZE count)
    {
        this->delta += count;
    }

    void decreaseDelta(SIZE count)
    {
        this->delta -= count;
    }

    void rebaseData(SIZE count)
    {
        memcpy(this->buffer, this->buffer + count, SOCKET_MAX_BUFFER_SIZE - count);
    }

public:
    Socket() : fd(-1),
               buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
               delta(0){};

    // Socket(int fd) : fd(fd),
    //                  buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
    //                  delta(0){};
                     
    // Socket(const std::string &host, const std::string port) : fd(-1),
    //                                                           buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
    //                                                           delta(0),
    //                                                           host(host),
    //                                                           port(port)
    // {
    //     // this->createConnection(host, port);
    // };

    virtual ~Socket()
    {
        delete[] buffer;
        buffer = 0;
    }

    virtual int createConnection(const std::string &host, const std::string &port);

    virtual void wrap(int fd) { this->fd = fd; };

    int getFd() const { return this->fd; }

    void closeSocket()
    {
        close(this->fd);
        this->fd = -1;
    };

    bool isConnected() const { return this->fd > 0; }

    virtual ssize_t writeData(const MessageBuilder &mb) const;

    virtual ssize_t writeData(const BYTE *data, SIZE datalen) const;

    ssize_t readData(MessageParser &mp);

    virtual const CHAR *getCipher() const { return "(NONE)"; }

    static SIZE getMaxSocketBuffRead() { return SOCKET_MAX_BUFFER_SIZE; }
};

#endif