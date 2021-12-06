#include "./tls_server.hh"

#include "../onion_routing/onion_routing_app.hh"

#include "../networking/network_bridge.hh"

#include "../util/cmd.hh"
#include "../util/debug.hh"

#include <iostream>

using namespace std;

int main(int argc, char **argv)
{
    const char *pubkey = getCmdOption(argv, argc, "-pubkey");

    if (not pubkey)
    {
        ERROR("Server public key is missing.");
        return EXIT_FAILURE;
    }

    const char *privkey = getCmdOption(argv, argc, "-privkey");

    if (not privkey)
    {
        ERROR("Server private key is missing.");
        return EXIT_FAILURE;
    }

    const char *host = getCmdOption(argv, argc, "-host");

    if (not host)
    {
        WARNING("No host provided; defaulting to localhost.");
        host = "localhost";
    }

    const char *port = getCmdOption(argv, argc, "-port");

    if (not port)
    {
        WARNING("No port provided; defaulting to 8080.");
        port = "8080";
    }

    Server *server = new Server(host, port);

    OnionRoutingApp &app = OnionRoutingApp::createApp(pubkey, privkey);
    NetworkBridge &networkBridge = NetworkBridge::createNetworkBridge(pubkey, privkey);

    app.attachNetworkBridge(&networkBridge);

    const char *netfile = getCmdOption(argv, argc, "-netfile");

    if (netfile)
    {
        app.joinNetwork(netfile);
    }
    else
    {
        FAILURE("No netfile provided; network connection failed.");
    }

    server->attachApp(&app);

    if (server->socketBind() < 0)
    {
        ERROR("Binding error.");
        return EXIT_FAILURE;
    }

    INFO("Local address: ", app.getAddress());
    INFO("Listening on ", host, ":", port);

    server->acceptClients();

    return EXIT_SUCCESS;
}