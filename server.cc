#include "server.hh"

#include <iostream>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>

Server::Server() : host(new char[MAX_HOST]),
                   port(new char[MAX_PORT]),
                   addrinf(new addrinfo),
                   backlog(backlog) {}

Server::Server(const char *host,
               const char *port,
               const addrinfo *addr_info,
               int backlog) : host(new char[MAX_HOST]),
                              port(new char[MAX_PORT]),
                              addrinf(new addrinfo),
                              backlog(backlog)
{
    host and strcpy(this->host, host);
    port and strcpy(this->port, port);

    addr_info and memcpy(this->addrinf, addr_info, sizeof(addrinfo));
}

Server::Server(const Server &s) : host(new char[MAX_HOST]),
                                  port(new char[MAX_PORT]),
                                  addrinf(new addrinfo)
{
    s.host and strcpy(this->host, s.host);
    s.port and strcpy(this->port, s.port);

    s.addrinf and memcpy(this->addrinf, s.addrinf, sizeof(addrinfo));

    this->backlog = s.backlog;
}

Server::~Server()
{
    delete this->host;
    delete this->port;
    delete this->addrinf;
}

void Server::set_host(const char *host)
{
    host and strcpy(this->host, host);
}

void Server::set_unix_socket_addr(const char *addr, size_t addrlen)
{
    addr and memcpy(this->host, addr, addrlen);
    this->addrlen = addrlen;
}

void Server::set_port(const char *port)
{
    port and strcpy(this->port, port);
}

void Server::set_addr_info(const addrinfo *addr)
{
    addr and memcpy(this->addrinf, addr, sizeof(addrinfo));
}

void Server::set_backlog(int backlog)
{
    this->backlog = backlog;
}

void Server::attach(App *app)
{
    this->app = app;
}

const char *Server::get_host() const
{
    return this->host;
}

const char *Server::get_port() const
{
    return this->port;
}

const addrinfo *Server::get_addr_info() const
{
    return this->addrinf;
}

int Server::get_backlog() const
{
    return this->backlog;
}

int Server::socket_bind()
{
    int reuse_address = 1;

    addrinfo *res = new addrinfo;
    addrinfo *p;

    if (not this->host or not this->port or not this->addrinf)
    {
        return -1;
    }

    if (getaddrinfo(host, port, this->addrinf, &res) != 0)
    {
        return -1;
    }

    for (p = res; p != NULL; p = res->ai_next)
    {
        if ((this->servsock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        {
            continue;
        }

        if ((setsockopt(this->servsock, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address))) < 0)
        {
            continue;
        }

        if (bind(this->servsock, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }

        close(this->servsock);
    }

    if (not p)
    {
        return -1;
    }

    freeaddrinfo(res);

    return 0;
}

int Server::unix_socket_bind()
{
    sockaddr_un addr;

    if (not this->host)
    {
        return -1;
    }

    if ((this->servsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        return -1;
    }

    int reuse_address = 1;
    if (setsockopt(this->servsock, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse_address, sizeof(reuse_address)) < 0)
    {
        return -1;
    }

    memset(&addr, 0, sizeof(sockaddr_un));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, this->host, this->addrlen);

    return bind(this->servsock, (sockaddr *)&addr, sizeof(sockaddr_un));
}

int Server::accept_clients()
{
    listen(this->servsock, this->backlog);

    int clientsock;
    sockaddr peer_addr;
    socklen_t peer_addrlen;

    while (true)
    {
        clientsock = accept(this->servsock, &peer_addr, &peer_addrlen);

        if (not this->app)
        {
            break;
        }

        this->app->handle_client(clientsock);
    }

    return clientsock;
}

Server &Server::operator=(const Server &s)
{
    if (this != &s)
    {
        delete this->host;
        delete this->port;
        delete this->addrinf;

        this->host = new char[128];
        this->port = new char[16];
        this->addrinf = new addrinfo;

        s.host and strcpy(this->host, s.host);
        s.port and strcpy(this->port, s.port);

        s.addrinf and memcpy(this->addrinf, s.addrinf, sizeof(addrinfo));

        this->backlog = s.backlog;
    }

    return *this;
}