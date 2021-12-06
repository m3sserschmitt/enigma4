#ifndef TLS_SOCKET_CLIENT_HH
#define TLS_SOCKET_CLIENT_HH

#include "tls_socket.hh"

// https://aticleworld.com/ssl-server-client-using-openssl-in-c/

class TlsSocketClient : public TlsSocket
{
    int initSllContext()
    {
        const SSL_METHOD *method = TLS_client_method();

        if (not method)
        {
            return -1;
        }

        if (not(this->sslContext = SSL_CTX_new(method)))
        {
            return -1;
        }

        return 0;
    }

    int createSsl()
    {
        return (this->ssl = SSL_new(this->sslContext)) ? 0 : -1;
    }

    // declare private copy constructor & operator= to prevent object copy
    TlsSocketClient(const TlsSocketClient &);

    const TlsSocketClient &operator=(const TlsSocketClient &);

public:
    TlsSocketClient() : TlsSocket() { this->initSllContext(); }

    int createConnection(const std::string &host, const std::string &port)
    {
        if (Socket::createConnection(host, port) < 0)
        {
            return -1;
        }

        if(this->createSsl() < 0)
        {
            return -1;
        }

        if (this->wrap(this->getFd()) < 0)
        {
            return -1;
        }

        return SSL_connect(this->ssl) <= 0 ? -1 : 0;
    }
};

#endif
