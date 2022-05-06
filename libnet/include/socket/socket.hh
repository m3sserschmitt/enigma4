#ifndef SOCKET_HH
#define SOCKET_HH

#include "message/message_parser.hh"
#include "message/message_builder.hh"
// #include "../../util/debug.hh"

#include <math.h>
#include <unistd.h>

class Socket
{
    static const SIZE SOCKET_MAX_BUFFER_SIZE = 4096;
    static const SIZE MAX_FAILED_READ_ATTEMPTS = 128;

    // file descriptor used to read and write data
    int fd;

    // buffer used to store extra bytes when more data read than required
    BYTES extraBytesBuffer;

    // size of extraBytesBuffer in bytes
    int delta;

    virtual ssize_t readSocket(int fd, size_t nbytes)
    {
        return read(this->fd, this->extraBytesBuffer, SOCKET_MAX_BUFFER_SIZE);
    }

    /**
     * @brief When more data than required are read from socket, they are storead into local buffer
     * and this method is called to recover those extra bytes of data from previous read operation
     *
     * @param mp Message object to store read byte from local buffer
     * @return ssize_t number of bytes read from local buffer
     */
    ssize_t readLocalBuffer(MessageParser &mp);

    /**
     * @brief Read socket data
     *
     * @param mp Message object to store bytes read from socket
     * @return ssize_t number of byte read
     */
    virtual ssize_t readNetworkData(MessageParser &mp);

    Socket(const Socket &);

    const Socket &operator=(const Socket &s);

protected:
    BYTES getBufferPtr() { return this->extraBytesBuffer; };

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
        memcpy(this->extraBytesBuffer, this->extraBytesBuffer + count, SOCKET_MAX_BUFFER_SIZE - count);
    }

public:
    Socket() : fd(-1),
               extraBytesBuffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
               delta(0){};

    virtual ~Socket()
    {
        delete[] extraBytesBuffer;
        extraBytesBuffer = 0;
    }

    virtual int createConnection(const std::string &host, const std::string &port, bool nonBlocking = false);

    int getFd() const { return this->fd; }

    const BYTE *getBuffer() const { return this->extraBytesBuffer; }

    virtual void closeSocket()
    {
        close(this->fd);
        this->fd = -1;
    };

    bool isConnected() const { return this->fd >= 0; }

    virtual int wrap(int fd)
    {
        this->fd = fd;
        return 0;
    };

    virtual ssize_t writeData(const MessageBuilder &mb) const;

    virtual ssize_t writeData(const BYTE *data, SIZE datalen) const;

    virtual ssize_t readData(MessageParser &mp);

    virtual const std::string getCipher() const { return "(NONE)"; }

    static SIZE getMaxSocketBuffRead() { return SOCKET_MAX_BUFFER_SIZE; }
};

#endif