#include "tls_client.hh"

#include "../networking/tls_socket.hh"

int TLSClient::setup_socket(const std::string &host, const std::string &port)
{
    if(this->get_socket())
    {
        return -1;
    }

    this->set_socket(new TLSSocket(host, port));
    
    return 0;
}