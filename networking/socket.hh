#ifndef SOCKET_HH
#define SOCKET_HH

#include "../protocol/message_parser.hh"
#include "../protocol/message_builder.hh"
#include "../util/debug.hh"
#include <unistd.h>

class Socket
{
    static const SIZE SOCKET_MAX_BUFFER_SIZE = 2048;

    int fd;
    BYTES buffer;
    int delta;

    ssize_t read_local_buffer(MessageParser &mp);

    virtual ssize_t read_data(MessageParser &mp)
    {
        ssize_t bytes_read = read(this->fd, this->buffer, SOCKET_MAX_BUFFER_SIZE);
        //INFO("bytes read: ", bytes_read);

        if (bytes_read <= 0)
        {
            return -1;
        }

        SIZE parsed;

        if (not mp.get_payload_size())
        {
            parsed = mp.update(this->buffer, bytes_read);
        }
        else
        {
            parsed = mp.append_payload(this->buffer, bytes_read);
        }

        this->increase_delta(bytes_read - parsed);
        this->rebase_data(parsed);

        return parsed;
    }

    Socket(const Socket &);
    const Socket &operator=(const Socket &s);

protected:
    BYTES get_buffer() { return this->buffer; };

    void set_delta(int delta) { this->delta = delta; }
    int get_delta() { return this->delta; }

    void increase_delta(SIZE count)
    {
        this->delta += count;
    }

    void decrease_delta(SIZE count)
    {
        this->delta -= count;
    }


    void rebase_data(SIZE count)
    {
        memcpy(this->buffer, this->buffer + count, SOCKET_MAX_BUFFER_SIZE - count);
    }

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

    bool is_connected() const { return this->fd > 0; }

    virtual ssize_t write_data(const MessageBuilder &mb) const;

    virtual ssize_t write_data(const BYTE *data, SIZE datalen) const;

    ssize_t read_network_data(MessageParser &mp);

    virtual const CHAR *get_cipher() const { return "(NONE)"; }

    static SIZE get_max_socket_buff_read() { return SOCKET_MAX_BUFFER_SIZE; }

    Socket *make_socket_copy() const
    {
        Socket *copy = new Socket;

        copy->fd = this->fd;
        memcpy(copy->buffer, this->buffer, SOCKET_MAX_BUFFER_SIZE);
        copy->delta = this->delta;

        return copy;
    }
};

#endif