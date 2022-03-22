#ifndef TLS_O_SOCKET_HH
#define TLS_O_SOCKET_HH

#include "socket.hh"

#include <openssl/ssl.h>

class TlsSocket : public Socket
{
    ssize_t readSocket(int fd, size_t nbytes)
    {
        return SSL_read(this->ssl, this->getBufferPtr(), nbytes);
    }

    TlsSocket(const TlsSocket &s);

    const TlsSocket &operator=(const TlsSocket &);

protected:
    SSL *ssl;
    SSL_CTX *sslContext;

public:
    TlsSocket() : Socket()
    {
        this->ssl = 0;
        this->sslContext = 0;
    }

    virtual ~TlsSocket() = 0;

    int wrap(int fd)
    {
        Socket::wrap(fd);

        return SSL_set_fd(this->ssl, this->getFd()) ? 0 : -1;
    }

    ssize_t writeData(const MessageBuilder &mb) const
    {
        return SSL_write(this->ssl, mb.getData(), mb.getDatalen());
    }

    ssize_t writeData(const BYTE *data, SIZE datalen) const
    {
        return SSL_write(this->ssl, data, datalen);
    }

    void closeSocket()
    {
        if (this->ssl)
        {
            SSL_shutdown(this->ssl);
            SSL_free(this->ssl);

            this->ssl = 0;
        }

        if (this->sslContext)
        {
            SSL_CTX_free(this->sslContext);

            this->sslContext = 0;
        }

        Socket::closeSocket();
    }

    virtual const std::string getCipher() const { return SSL_get_cipher(ssl); };
};

#endif
