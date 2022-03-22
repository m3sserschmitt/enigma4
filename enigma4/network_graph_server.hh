#ifndef NETWORK_GRAPH_SERVER_HH
#define NETWORK_GRAPH_SERVER_HH

#include "server.hh"
#include "socket/bridge_socket.hh"

class NetworkGraphServer : public Server
{
    Socket *makeSocket(int clientSocketFd)
    {
        Socket *sock = new BridgeSocket();
        sock->wrap(clientSocketFd);

        return sock;
    }

public:
    NetworkGraphServer(const std::string &socketFile) : Server(socketFile) {}
};

#endif
