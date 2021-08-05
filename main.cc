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

    Server *server = new Server("192.168.43.165", "8080", addrinf);
    // Server *local_server = new Server;

    OnionRoutingApp &app = OnionRoutingApp::get_handle("server_public.pem", "server_private.pem");

    server->attach(&app);

    if (server->socket_bind() < 0)
    {
        cout << "[-] Bind error\n";

        return EXIT_FAILURE;
    }

    server->accept_clients();

    // local_server->attach(&app);

    // local_server->set_unix_socket_addr("local_server_sock", 18);
    // local_server->unix_socket_bind();
    // local_server->accept_clients();

    return EXIT_SUCCESS;
}