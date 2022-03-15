#ifndef NETWORK_GRAPH_BRIDGE_HH
#define NETWORK_GRAPH_BRIDGE_HH

#include "onion_routing_app.hh"

class NetworkGraphBridge : public OnionRoutingApp
{

    NetworkGraphBridge(): OnionRoutingApp() {}
    ~NetworkGraphBridge() {}

public:

    static NetworkGraphBridge &createApp()
    {
        static NetworkGraphBridge bridge;

        return bridge;
    }

    int handleClient(Socket *sock)
    {
        pthread_t thread;
        Connection *connection = new Connection(sock);

        connection->setConnectionPeerType(NETWORK_GRAPH_PEER);

        return pthread_create(&thread, 0, OnionRoutingApp::newThread, (void *)connection) == 0 ? 0 : -1;
    }
};

#endif
