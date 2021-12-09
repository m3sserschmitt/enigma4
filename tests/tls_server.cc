#include "../enigma4/tls_server.hh"

using namespace std;

int main()
{
    TlsServer *server = new TlsServer();

    server->useCertificateFile("cert.pem");
    server->usePrivateKeyFile("key.pem");

    server->socketBind();
    server->acceptClients();
    

    return 0;
}