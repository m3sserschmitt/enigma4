#ifndef O_SOCKET_HH
#define O_SOCKET_HH

#include "message_parser.hh"
#include "message_builder.hh"
#include <unistd.h>

#define O_SOCKET_MAX_BUFFER_SIZE 2048

class OSocket
{
    int fd;
    BYTES buffer;
    SIZE offset;
    int delta;

    OSocket(const OSocket &s){};
    const OSocket &operator=(const OSocket &s) { return *this; };

    ssize_t read_buffer(MessageParser &mp);

public:
    OSocket() : fd(-1), buffer(new BYTE[O_SOCKET_MAX_BUFFER_SIZE]), delta(0), offset(0){};
    OSocket(int fd) : fd(fd), buffer(new BYTE[O_SOCKET_MAX_BUFFER_SIZE]), delta(0), offset(0){};

    void wrap(int fd) { this->fd = fd; };
    void close_fd() { close(this->fd); };

    ssize_t write_data(const MessageBuilder &mb) const;
    ssize_t write_data(const BYTE *data, SIZE datalen) const;
    ssize_t read_data(MessageParser &mp);
};

#endif