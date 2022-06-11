#include <iostream>

#include "enigma4-client/tls_client.hh"

using namespace std;

int main(int argc, char **argv)
{

    const char *guardIP = argv[1];
    const char *guardPort = argv[2];
    const char *guardPublicKeyFile = argv[3];
    const char *nodePublicKeyFile = argv[4];

    CRYPTO::RSA_generate_keys("client_public.pem", "client_private.pem", 2048, 0, 0, 0, 0);

    TlsClient client;
    client.setClientPublicKeyFile("client_public.pem");
    client.loadClientPrivateKeyFile("client_private.pem");

    client.createConnection2(guardIP, guardPort, guardPublicKeyFile);

    NetworkNode *node = client.setupNetworkNode2(nodePublicKeyFile);
    client.addNodeToCircuit(node, client.getGuardAddress());
    client.addNewSession(node);

    return 0;
}