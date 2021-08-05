#ifndef SERVER_H
#define SERVER_H

#include "app.h"
#include <netdb.h>

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

public:

    Server();
    Server(const char *host, const char *port, const addrinfo *addr_info, int backlog = 256);
    Server(const Server &s);

    ~Server();

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
    int accept_clients();

    Server &operator=(const Server &s);
};

#endif
