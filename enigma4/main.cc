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
        INFO("No host provided; defaulting to localhost.");
        host = "localhost";
    }

    const char *port = getCmdOption(argv, argc, "-port");

    if (not port)
    {
        INFO("No port provided; defaulting to 8080.");
        port = "8080";
    }

    const char *certificateFile = getCmdOption(argv, argc, "-certificate");

    Server *server;

    if (not certificateFile)
    {
        WARNING("No public certificate file provided.");
        WARNING("Starting non-TLS server...");

        server = new Server(host, port);
    }
    else
    {
        INFO("Starting TLS server...");

        server = new TlsServer(host, port);

        if (server->useCertificateFile(certificateFile) < 0)
        {
            ERROR("Failed to load certificate file: ", certificateFile);

            return EXIT_FAILURE;
        }

        SUCCESS("Certificate file successfully loaded: ", certificateFile);

        if(server->usePrivateKeyFile(privkey) < 0)
        {
            ERROR("Failed to load private key file: ", privkey);

            return EXIT_FAILURE;
        }

        SUCCESS("Private key file successfully loaded: ", privkey);
    }

    OnionRoutingApp &app = OnionRoutingApp::createApp(pubkey, privkey);

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
    SUCCESS("Listening on ", host, ":", port);

    

    server->acceptClients();

    return EXIT_SUCCESS;
}