#include "server.hh"
#include "onion_routing.hh"
#include "cmd.hh"
#include "debug.hh"

#include <iostream>

using namespace std;

int main(int argc, char **argv)
{

    const char *pubkey = get_cmd_option(argv, argc, "-pubkey");

    if (not pubkey)
    {
        ERROR("Server public key is missing.");
        return EXIT_FAILURE;
    }

    const char *privkey = get_cmd_option(argv, argc, "-privkey");

    if (not privkey)
    {
        ERROR("Server private key is missing.");
        return EXIT_FAILURE;
    }

    const char *host = get_cmd_option(argv, argc, "-host");

    if (not host)
    {
        WARNING("No host provided; listening on localhost.");
        host = "localhost";
    }

    const char *port = get_cmd_option(argv, argc, "-port");

    if (not port)
    {
        WARNING("No port provided; listening on 8080.");
        port = "8080";
    }

    addrinfo *addrinf = new addrinfo;

    addrinf->ai_family = AF_INET;
    addrinf->ai_socktype = SOCK_STREAM;
    addrinf->ai_flags = 0;
    addrinf->ai_protocol = 0;

    Server *server = new Server(host, port, addrinf);
    OnionRoutingApp &app = OnionRoutingApp::get_handle(pubkey, privkey);

    server->attach(&app);

    if (server->socket_bind() < 0)
    {
        ERROR("Binding error.");
        return EXIT_FAILURE;
    }

    INFO("Local address: " << app.get_address());
    INFO("Listening on " << host << ":" << port);
    
    server->accept_clients();

    return EXIT_SUCCESS;
}