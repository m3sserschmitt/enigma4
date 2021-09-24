#ifndef SOCKET_HH
#define SOCKET_HH

#include "message_parser.hh"
#include "message_builder.hh"

#include <unistd.h>
#include <string>

class Socket
{
    static const SIZE SOCKET_MAX_BUFFER_SIZE = 2048;

    int fd;
    BYTES buffer;
    int delta;

    bool connected;

    ssize_t read_buffer(MessageParser &mp);
    virtual ssize_t read_data();

protected:
    BYTES get_buffer() { return this->buffer; };

    void set_delta(int delta) { this->delta = delta; }
    int get_delta() { return this->delta; }

public:
    Socket() : fd(-1),
               buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
               delta(0){};
    Socket(int fd) : fd(fd),
                     buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
                     delta(0){};
    Socket(const std::string &host, const std::string port) : fd(-1),
                                                              buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
                                                              delta(0)
    {
        this->create_connection(host, port);
    };
    Socket(const Socket &s) : fd(s.fd),
                              buffer(new BYTE[SOCKET_MAX_BUFFER_SIZE]),
                              delta(s.delta)
    {
        memcpy(this->buffer, s.buffer, SOCKET_MAX_BUFFER_SIZE);
    }
    virtual ~Socket()
    {
        delete[] buffer;
    }

    virtual int create_connection(const std::string &host, const std::string &port);

    virtual void wrap(int fd) { this->fd = fd; };
    int get_fd() const { return this->fd; }
    void close_fd()
    {
        close(this->fd);
        this->fd = -1;
    };

    virtual ssize_t write_data(const MessageBuilder &mb) const;
    virtual ssize_t write_data(const BYTE *data, SIZE datalen) const;
    ssize_t read_data(MessageParser &mp);

    virtual const CHAR *get_cipher() const { return "(NONE)"; }
    static SIZE get_max_socket_buff_read() { return SOCKET_MAX_BUFFER_SIZE; }

    const Socket &operator=(const Socket &s);
};

#endif