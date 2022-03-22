#include "socket/tls_socket.hh"

TlsSocket::~TlsSocket()
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
}