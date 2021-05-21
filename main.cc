#include "server.hh"
#include "onion_routing.hh"
#include "message.hh"

#include "cryptography.hh"

#include <iostream>

using namespace std;

int main()
{
    BYTES der_key = 0;
    string PEM = "-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojYb5h0vm9YEK5sDO6fJ\n"\
"CH0qFik8p7yB2XTqA0rj1v52+trmMWxI5X3JmFUCMr+vx+kiwBTcud4AwrvkcV3o\n"\
"4Vi4zgr/UbV04D1VddCGxrTPkelKqKbQCYPIVtzJ5ZJtPBPaCgoBHgy9K/wYIfnS\n"\
"77ybULYJFFDKEgcI6sjPlYg/PTYQKzsqRRYE2Ec/ctALOWL56ZA31pkdih9xhuID\n"\
"gon4el4s31oaAoUHaF7eUR8iWIjvFMsdzm8GSYvZJTkQzMy9YiSrQUXhNXzOiV1P\n"\
"A9cp8YQ2KaB1f5Tj648c9TaChdwzA+5MZPUmeQve+stwm8h+CreIMbiRAQ2Mf0HU\n"\
"OQIDAQAB\n"\
"-----END PUBLIC KEY-----";
    cout << PEM_key_to_DER(PEM, &der_key) << "\n";
    

    // RSA_CRYPTO ctx = RSA_CRYPTO_new();

    // addrinfo *addrinf = new addrinfo;

    // addrinf->ai_family = AF_INET;
    // addrinf->ai_socktype = SOCK_STREAM;
    // addrinf->ai_flags = 0;
    // addrinf->ai_protocol = 0;

    // Server &server = Server::create_server("127.0.0.1", "8080", addrinf, 256);
    // OnionRoutingApp &app = OnionRoutingApp::create_app();

    // server.attach(&app);
    // server.socket_bind();
    // server.accept_clients();

    return 0;
}