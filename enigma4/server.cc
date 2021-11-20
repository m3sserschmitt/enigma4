#include "server.hh"

#include <unistd.h>
#include <sys/un.h>


int Server::socketBind()
{
    int reuse_address = 1;

    addrinfo *res = new addrinfo;
    addrinfo *p;

    if (not this->host.size() or not this->port.size() or not this->addrInfo)
    {
        return -1;
    }

    if (getaddrinfo(host.c_str(), port.c_str(), this->addrInfo, &res) != 0)
    {
        return -1;
    }

    for (p = res; p != nullptr; p = res->ai_next)
    {
        if ((this->servsock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        {
            close(this->servsock);
            
            continue;
        }

        if ((setsockopt(this->servsock, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address))) < 0)
        {
            close(this->servsock);

            continue;
        }

        if (bind(this->servsock, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }
    }

    if (not p)
    {
        return -1;
    }

    freeaddrinfo(res);

    return 0;
}

int Server::unixSocketBind()
{
    sockaddr_un addr;

    if (not this->host.size())
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
    strncpy(addr.sun_path, this->host.c_str(), this->host.size());

    return bind(this->servsock, (sockaddr *)&addr, sizeof(sockaddr_un));
}

int Server::acceptClients()
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

        this->app->handleClient(clientsock);
    }

    return clientsock;
}
