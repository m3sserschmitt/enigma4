#include "server.hh"
#include "onion_routing.hh"
#include "message_parser.hh"

#include <iostream>
#include <netdb.h>

using namespace std;

int main()
{
    addrinfo *addrinf = new addrinfo;

    addrinf->ai_family = AF_INET;
    addrinf->ai_socktype = SOCK_STREAM;
    addrinf->ai_flags = 0;
    addrinf->ai_protocol = 0;

    Server *server = new Server("127.0.0.1", "8080", addrinf);
    OnionRoutingApp &app = OnionRoutingApp::get_handle("server_public.pem", "server_private.pem");

    server->attach(&app);

    if (server->socket_bind() < 0)
    {
        cout << "[-] Bind error\n";

        return EXIT_FAILURE;
    }

    server->accept_clients();

    return EXIT_SUCCESS;
}