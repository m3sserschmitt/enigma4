#include "server.hh"

#include <unistd.h>
#include <sys/un.h>

#include "socket/socket.hh"
#include "util/debug.hh"

int Server::socketBind()
{
    // if no port provided, try creating UNIX socket domain server;
    if(not this->port.size() and this->host.size())
    {
        return this->unixSocketBind();
    }

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
    size_t len = strlen(addr.sun_path) + sizeof(addr.sun_family);

    unlink(this->host.c_str());

    return bind(this->servsock, (sockaddr *)&addr, len);
}

void *Server::serverInfiniteLoop(void *args)
{
    if(not args)
    {
        return 0;
    }

    Server *server = (Server *)args;

    while (true)
    {
        Socket *sock = server->acceptClient();

        if(not sock)
        {
            return 0;
        }

        server->app->handleClient(sock);
    }

    return 0;
}

int Server::acceptClients()
{
    listen(this->servsock, this->backlog);

    return pthread_create(&this->infiniteLoopThread, 0, this->serverInfiniteLoop, this) == 0 ? 0 : -1;
}
