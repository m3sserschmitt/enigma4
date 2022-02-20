#include "tls_server.hh"
#include "onion_routing_app.hh"

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

    const char *certificateFile = getCmdOption(argv, argc, "-certificate");

    if (not certificateFile)
    {
        ERROR("No certificate file provided");

        return EXIT_FAILURE;
    }

    
    OnionRoutingApp &app = OnionRoutingApp::createApp(pubkey, privkey);
    //NetworkBridge &networkBridge = NetworkBridge::createNetworkBridge(pubkey, privkey);

    TlsServer *server = new TlsServer(host, port);
    
    server->useCertificateFile(certificateFile);
    server->usePrivateKeyFile(privkey);

    //app.attachNetworkBridge(&networkBridge);
    server->attachApp(&app);

    const char *netfile = getCmdOption(argv, argc, "-netfile");

    if (netfile)
    {
        app.joinNetwork(netfile);
    }
    else
    {
        FAILURE("No netfile provided; network connection failed.");
    }

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