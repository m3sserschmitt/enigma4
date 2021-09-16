#ifndef TLS_O_SOCKET_HH
#define TLS_O_SOCKET_HH

#include "socket.hh"

#include <openssl/ssl.h>

class TLSSocket : public Socket
{
    SSL_CTX *ctx;
    SSL *ssl;

    int ssl_init();
    int ssl_wrap_fd();

    ssize_t read_data();
    ssize_t write_data(const MessageBuilder &mb) const;
    ssize_t write_data(const BYTE *data, SIZE datalen) const;

public:
    TLSSocket() : Socket() { this->ssl_init(); };
    TLSSocket(int fd) : Socket(fd)
    {
        this->ssl_init();
        this->ssl_wrap_fd();
    }
    TLSSocket(const std::string host, const std::string &port) : Socket(host, port)
    {
        this->ssl_init();
        this->ssl_wrap_fd();
    }

    int create_connection(const std::string &host, const std::string &port)
    {
        if (Socket::create_connection(host, port) < 0)
        {
            return -1;
        }

        return this->ssl_wrap_fd();
    }

    const CHAR *get_cipher() const { return SSL_get_cipher(ssl); };

    void wrap(int fd)
    {
        Socket::wrap(fd);
        this->ssl_wrap_fd();
    };
};

#endif
