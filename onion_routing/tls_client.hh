#ifndef TLS_CLIENT_HH
#define TLS_CLIENT_HH

#include "client.hh"

class TLSClient : public Client
{
    int setupSocket(const std::string &host, const std::string &port);

    TLSClient(const TLSClient &c);
    const TLSClient &operator=(const TLSClient &c);

public:
    TLSClient(const std::string &pubkey, const std::string &privkey) : Client(pubkey, privkey) {}
};

#endif
