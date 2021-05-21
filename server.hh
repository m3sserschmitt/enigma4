#include "app.h"

#ifndef SERVER_H
#define SERVER_H

#define MAX_HOST 256
#define MAX_PORT 8

class Server
{
private:

    char *host;
    char *port;
    addrinfo *addrinf;
    int backlog;

    int servsock;
    int addrlen;

    App *app;

    Server(const char *host, const char *port, const addrinfo *addr_info, int backlog = 256);
    Server(const Server &s);
    ~Server();

    Server &operator=(const Server &s);

public:
    static Server &create_server(const char *host, const char *port, const addrinfo *addr, int backlog);

    void set_host(const char *host);
    void set_unix_socket_addr(const char *addr, size_t hostlen);
    void set_port(const char *port);
    void set_addr_info(const addrinfo *addr);
    void set_backlog(int backlog);

    void attach(App *app);

    const char *get_host() const;
    const char *get_port() const;
    const addrinfo *get_addr_info() const;
    int get_backlog() const;

    int socket_bind();
    int unix_socket_bind();
    client_t accept_clients();
};

#endif
