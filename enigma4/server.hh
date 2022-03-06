#ifndef SERVER_H
#define SERVER_H

#include "app.h"
#include "../net/sockets/tls_socket.hh"

#include <netdb.h>
#include <string>

class Server
{
    std::string host;
    std::string port;

    addrinfo *addrInfo;
    int backlog;

    int servsock;

    App *app;

    const Server &operator=(const Server &);
    Server(const Server &);

    virtual Socket *makeSocket(int clientSocketFd)
    {
        Socket *sock = new Socket();
        sock->wrap(clientSocketFd);

        return sock;
    }

    int unixSocketBind();

public:
    Server() : host("localhost"), port("8080"), backlog(128)
    {
        this->addrInfo = Server::makeDefaultAddrinfo();
    }

    Server(const std::string &host, const std::string &port) : host(host), port(port), backlog(128)
    {
        this->addrInfo = Server::makeDefaultAddrinfo();
    }

    Server(const std::string &socketFile) : host(socketFile), backlog(128) {}

    Server(const std::string &host, const std::string &port, const addrinfo *addrInfo, int backlog) : host(host), port(host), addrInfo(new addrinfo(*addrInfo)), backlog(backlog) {}

    ~Server() { delete this->addrInfo; }

    static addrinfo *makeDefaultAddrinfo()
    {
        addrinfo *new_addrinfo = new addrinfo;

        new_addrinfo->ai_family = AF_INET;
        new_addrinfo->ai_socktype = SOCK_STREAM;
        new_addrinfo->ai_flags = 0;
        new_addrinfo->ai_protocol = 0;

        return new_addrinfo;
    }

    void setPort(const std::string &port)
    {
        this->port = port;
    }

    void setAddrInfo(const addrinfo *addr)
    {
        delete this->addrInfo;
        this->addrInfo = new addrinfo(*addr);
    }

    void setBacklog(int backlog)
    {
        this->backlog = backlog;
    }

    const std::string &getHost() const
    {
        return this->host;
    }

    const std::string &getPort() const
    {
        return this->port;
    }

    const addrinfo *getAddrInfo() const
    {
        return this->addrInfo;
    }

    virtual int useCertificateFile(const std::string &certfile)
    {
        return -1;
    }

    virtual int usePrivateKeyFile(const std::string &privkeyfile)
    {
        return -1;
    }

    int getServerFd() const { return this->servsock; }

    int getBacklog() const
    {
        return this->backlog;
    }

    void attachApp(App *app)
    {
        this->app = app;
    }

    int socketBind();

    virtual Socket *acceptClient()
    {
        int clientSocket = accept(this->servsock, 0, 0);

        if (clientSocket < 0)
        {
            return 0;
        }

        return this->makeSocket(clientSocket);
    }

    int acceptClients();
};

#endif
