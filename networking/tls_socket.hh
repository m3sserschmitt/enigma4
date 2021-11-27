#ifndef TLS_O_SOCKET_HH
#define TLS_O_SOCKET_HH

#include "socket.hh"

#include <openssl/ssl.h>

class TLSSocket : public Socket
{
    SSL_CTX *ctx;
    SSL *ssl;

    int sslInit();

    int sslWrapFd();

    ssize_t readData();

    TLSSocket(const TLSSocket &s);

    const TLSSocket &operator=(const TLSSocket &);

public:
    TLSSocket() : Socket() { this->sslInit(); };

    // TLSSocket(int fd) : Socket(fd)
    // {
    //     this->sslInit();
    //     this->sslWrapFd();
    // }
    
    // TLSSocket(const std::string host, const std::string &port) : Socket(host, port)
    // {
    //     this->sslInit();
    //     this->sslWrapFd();
    // }

    ~TLSSocket()
    {
        SSL_CTX_free(ctx);
        SSL_free(ssl);
    }

    int createConnection(const std::string &host, const std::string &port)
    {
        if (Socket::createConnection(host, port) < 0)
        {
            return -1;
        }

        return this->sslWrapFd();
    }
    
    void wrap(int fd)
    {
        Socket::wrap(fd);
        this->sslWrapFd();
    };

    ssize_t writeData(const MessageBuilder &mb) const;
    
    ssize_t writeData(const BYTE *data, SIZE datalen) const;

    const CHAR *getCipher() const { return SSL_get_cipher(ssl); };
};

#endif
