
#ifndef APP_H
#define APP_H

#include <netdb.h>

typedef struct
{
    int sock;
    sockaddr peer_addr;
    socklen_t peer_addrlen;
} client_t;

class App
{
public:
    virtual ~App(){};
    virtual int handle_client(client_t) = 0;
};

#endif
