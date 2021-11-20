#include "tls_socket.hh"

int TLSSocket::sslInit()
{
    const SSL_METHOD *method = TLS_client_method();

    if (not method)
    {
        return -1;
    }

    this->ctx = SSL_CTX_new(method);

    if (not this->ctx)
    {
        return -1;
    }

    this->ssl = SSL_new(this->ctx);

    if (not this->ssl)
    {
        return -1;
    }

    return 0;
}

int TLSSocket::sslWrapFd()
{
    if (not SSL_set_fd(ssl, this->getFd()))
    {
        return -1;
    }

    if (SSL_connect(ssl) <= 0)
    {
        return -1;
    }

    return 0;
}

ssize_t TLSSocket::readData()
{
    SIZE delta = this->getDelta();
    BYTES buffer = this->getBuffer();

    return SSL_read(this->ssl, buffer + (delta > 0 ? delta : 0), Socket::getMaxSocketBuffRead());
}

ssize_t TLSSocket::writeData(const MessageBuilder &mb) const
{
    return SSL_write(this->ssl, mb.getData(), mb.getDatalen());
}

ssize_t TLSSocket::writeData(const BYTE *data, SIZE datalen) const
{
    return SSL_write(this->ssl, data, datalen);
}
