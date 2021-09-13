#include "server.hh"
#include "onion_routing.hh"
#include "cmd.hh"

#include <iostream>

using namespace std;

int main(int argc, char **argv)
{

    const char *pubkey = get_cmd_option(argv, argc, "-pubkey");

    if (not pubkey)
    {
        cout << "[-] Error: server public key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *privkey = get_cmd_option(argv, argc, "-privkey");

    if (not privkey)
    {
        cout << "[-] Error: server private key is missing.\n";
        return EXIT_FAILURE;
    }

    const char *host = get_cmd_option(argv, argc, "-host");

    if (not host)
    {
        cout << "[-] Warning: no host provided; listening on localhost.\n";
        host = "localhost";
    }

    const char *port = get_cmd_option(argv, argc, "-port");

    if (not port)
    {
        cout << "[-] Warning: no port provided; listening on 8080.\n";
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
        cout << "[-] Bind error\n";

        return EXIT_FAILURE;
    }

    cout << "[+] Listening on port " << host << ":" << port << "\n";
    server->accept_clients();

    return EXIT_SUCCESS;
}