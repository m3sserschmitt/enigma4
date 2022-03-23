#ifndef TLS_SOCKET_SERVER_HH
#define TLS_SOCKET_SERVER_HH

#include "tls_socket.hh"

class TlsServerSocket : public TlsSocket
{
    TlsServerSocket(const TlsServerSocket &);

    const TlsServerSocket &operator=(const TlsServerSocket &);

public:
    TlsServerSocket() : TlsSocket() {}

    int createConnection(const std::string &host, const std::string &port, bool nonBlocking = false)
    {
        return -1;
    }

    void useSll(SSL *ssl)
    {
        this->ssl = ssl;
    }

    int acceptSslClient()
    {
        return SSL_accept(this->ssl) <= 0 ? -1 : 0;
    }
};

#endif
