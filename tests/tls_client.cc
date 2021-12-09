#include "../onion_routing/tls_client.hh"

using namespace std;

int main()
{
    TlsClient *client = new TlsClient("client_public1.pem", "client_private1.pem");

    client->createConnection("localhost", "8080", "server_public1.pem", 0);

    cout << "cipher: " << client->getSocketCipher() << "\n";

    client->writeDataWithoutEncryption((BYTES)"hello server", 13);
    
    return 0;
}