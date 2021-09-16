#include "tls_socket.hh"

int TLSSocket::ssl_init()
{
    // SSL_library_init();
    // SSLeay_add_ssl_algorithms();
    // SSL_load_error_strings();

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

int TLSSocket::ssl_wrap_fd()
{
    if (not SSL_set_fd(ssl, this->get_fd()))
    {
        return -1;
    }

    if (SSL_connect(ssl) <= 0)
    {
        return -1;
    }

    return 0;
}

ssize_t TLSSocket::read_data()
{
    SIZE delta = this->get_delta();
    BYTES buffer = this->get_buffer();

    return SSL_read(this->ssl, buffer + (delta > 0 ? delta : 0), O_SOCKET_MAX_BUFFER_SIZE);
}

ssize_t TLSSocket::write_data(const MessageBuilder &mb) const
{
    return SSL_write(this->ssl, mb.get_data(), mb.get_datalen());
}

ssize_t TLSSocket::write_data(const BYTE *data, SIZE datalen) const
{
    return SSL_write(this->ssl, data, datalen);
}
