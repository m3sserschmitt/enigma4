#include "onion_routing.hh"

#include <iostream>
#include <unistd.h>
#include <string.h>

using namespace std;

OnionRoutingApp::OnionRoutingApp() {}

OnionRoutingApp::~OnionRoutingApp() {}

OnionRoutingApp &OnionRoutingApp::create_app()
{
    static OnionRoutingApp app = OnionRoutingApp();

    return app;
}

void *OnionRoutingApp::new_thread(void *args)
{
    connection_t *connection = ((connection_t *)args);
    char *recvdata = new char[4096];

    while (read(connection->client.sock, recvdata, 4096) > 0)
    {
        cout << recvdata << "\n";

        memset(recvdata, 0, 4096);
    }

    return 0;
}

int OnionRoutingApp::handle_client(client_t client)
{
    pthread_t thread;

    connection_t *connection = new connection_t;
    connection->client = client;

    return not pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
