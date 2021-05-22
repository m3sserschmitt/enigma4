#include "server.hh"
#include "onion_routing.hh"
#include "message.hh"

#include "cryptography.hh"

#include <iostream>

using namespace std;

int main()
{
    addrinfo *addrinf = new addrinfo;

    addrinf->ai_family = AF_INET;
    addrinf->ai_socktype = SOCK_STREAM;
    addrinf->ai_flags = 0;
    addrinf->ai_protocol = 0;

    Server &server = Server::create_server("192.168.43.165", "8080", addrinf, 256);
    OnionRoutingApp &app = OnionRoutingApp::create_app();

    server.attach(&app);
    server.socket_bind();
    server.accept_clients();

    return 0;
}