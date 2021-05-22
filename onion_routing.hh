#include "app.h"

#ifndef ONION_ROUTING_H
#define ONION_ROUTING_H

typedef struct
{
    client_t client;
} connection_t;


class OnionRoutingApp : public App
{
    OnionRoutingApp();
    ~OnionRoutingApp();

    static void *new_thread(void *);

public:
    static OnionRoutingApp &create_app();
    int handle_client(client_t client);
};

#endif