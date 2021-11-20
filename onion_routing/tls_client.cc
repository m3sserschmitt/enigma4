#include "tls_client.hh"

#include "../networking/tls_socket.hh"

int TLSClient::setupSocket(const std::string &host, const std::string &port)
{
    if(this->getSocket())
    {
        return -1;
    }

    this->setSocket(new TLSSocket(host, port));
    
    return 0;
}