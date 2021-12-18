#ifndef TLS_SERVER_HH
#define TLS_SERVER_HH

#include "server.hh"
#include "../net/sockets/tls_socket_server.hh"

#include <openssl/ssl.h>

// https://wiki.openssl.org/index.php/Simple_TLS_Server

class TlsServer : public Server
{
    SSL_CTX *sslContext;

    int initSslContext()
    {
        const SSL_METHOD *method = TLS_server_method();

        if (not(this->sslContext = SSL_CTX_new(method)))
        {
            return -1;
        }

        return 0;
    }

    SSL *cratePendingConnectionSSL()
    {
        if (not this->sslContext)
        {
            return 0;
        }

        return SSL_new(this->sslContext);
    }

    Socket *makeSocket(int clientSocketFd)
    {
        SSL *pendingConnectionSSL = this->cratePendingConnectionSSL();

        if (not pendingConnectionSSL)
        {
            return 0;
        }

        TlsServerSocket *sock = new TlsServerSocket();

        sock->useSll(pendingConnectionSSL);

        if (sock->wrap(clientSocketFd) < 0)
        {
            return 0;
        }

        if (sock->acceptSslClient() < 0)
        {
            return 0;
        }

        return sock;
    }

public:
    TlsServer() : Server()
    {
        this->initSslContext();
    }

    TlsServer(const std::string &host, const std::string &port) : Server(host, port)
    {
        this->initSslContext();
    }

    TlsServer(const std::string &host, const std::string &port, const addrinfo *addrInfo, int backlog) : Server()
    {
        this->initSslContext();
    }

    int useCertificateFile(const std::string &certfile)
    {
        return SSL_CTX_use_certificate_file(this->sslContext, certfile.c_str(), SSL_FILETYPE_PEM) <= 0 ? -1 : 0;
    }

    int usePrivateKeyFile(const std::string &privkeyfile)
    {
        return SSL_CTX_use_PrivateKey_file(this->sslContext, privkeyfile.c_str(), SSL_FILETYPE_PEM) <= 0 ? -1 : 0;
    }
};

#endif
