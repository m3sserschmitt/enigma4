#include <iostream>
#include <string>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "client.hh"

#include <cryptography/cryptography.hh>

using namespace std;

void gen_keys()
{
    CRYPTO::RSA_generate_keys("client_public2.pem", "client_private2.pem", 4096, 0, 0, 0, 0);
}


int main()
{
    // gen_keys();

    Client client("client_public.pem");
    client.setup_server("server_public.pem");
    client.setup_dest("client_public2.pem");

    client.create_connection("192.168.43.165", "8080");
    
    client.handshake();
    client.setup_dest_key();

    // client.write_data((BYTES)"hello", 5);

    return 0;
}