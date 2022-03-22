#ifndef TLS_CLIENT_HH
#define TLS_CLIENT_HH

#include "client.hh"
#include "socket/tls_socket_client.hh"


class TlsClient : public Client
{
    void makeSocket()
    {
        this->clientSocket = new TlsSocketClient();
    }

    TlsClient(const TlsClient &c);
    const TlsClient &operator=(const TlsClient &c);

public:
    TlsClient(): Client() {}
    TlsClient(const std::string &pubkey, const std::string &privkey) : Client(pubkey, privkey) {}

    ~TlsClient() {}
};

#endif
