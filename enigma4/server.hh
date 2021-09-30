#ifndef SERVER_H
#define SERVER_H

#include "../onion_routing/app.h"

#include <netdb.h>
#include <string>

class Server
{
    std::string host;
    std::string port;

    addrinfo *addr_info;
    int backlog;

    int servsock;

    App *app;

    const Server &operator=(const Server &);
    Server(const Server &);

public:
    Server() : host("localhost"), port("8080"), backlog(128)
    {
        this->addr_info = Server::make_default_addrinfo();
    }
    Server(const std::string &host, const std::string &port) : host(host), port(port), backlog(128)
    {
        this->addr_info = Server::make_default_addrinfo();
    }
    Server(const std::string &host, const std::string &port, const addrinfo *addr_info, int backlog) : host(host), port(host), addr_info(new addrinfo(*addr_info)), backlog(backlog) {}

    ~Server() { delete this->addr_info; }

    static addrinfo *make_default_addrinfo()
    {
        addrinfo *new_addrinfo = new addrinfo;

        new_addrinfo->ai_family = AF_INET;
        new_addrinfo->ai_socktype = SOCK_STREAM;
        new_addrinfo->ai_flags = 0;
        new_addrinfo->ai_protocol = 0;

        return new_addrinfo;
    }

    void set_port(const std::string &port)
    {
        this->port = port;
    }
    void set_addr_info(const addrinfo *addr)
    {
        delete this->addr_info;
        this->addr_info = new addrinfo(*addr);
    }
    void set_backlog(int backlog)
    {
        this->backlog = backlog;
    }

    const std::string &get_host() const
    {
        return this->host;
    }
    const std::string &get_port() const
    {
        return this->port;
    }
    const addrinfo *get_addr_info() const
    {
        return this->addr_info;
    }
    int get_backlog() const
    {
        return this->backlog;
    }

    void attach_app(App *app)
    {
        this->app = app;
    }

    int socket_bind();
    int unix_socket_bind();
    int accept_clients();
};

#endif
