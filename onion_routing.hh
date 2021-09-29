#ifndef ONION_ROUTING_H
#define ONION_ROUTING_H

#include <cryptography/cryptography.hh>
#include <map>
#include <list>

#include "app.h"
#include "connection.hh"
#include "client.hh"

class OnionRoutingApp : public App
{
    static RSA_CRYPTO rsactx;

    static std::string pubkeyfile;
    static std::string privkeyfile;

    static std::string pubkey;
    static std::string address;

    static std::list<Client *> peers;
    static std::map<std::string, Connection *> clients;

    OnionRoutingApp(const std::string &pubkey_file, const std::string &privkey_file);
    ~OnionRoutingApp()
    {
        CRYPTO::RSA_CRYPTO_free(rsactx);
    }

    static int connect_peer(const std::string &host, const std::string &port, const std::string &pubkeyfile);

    static int setup_session(MessageParser &mp, Connection *conn);
    static int try_handshake(MessageParser &mp, Connection *conn);
    static int action(MessageParser &mp, Connection *conn);

    static int forward_message(MessageParser &mp);

    static int redirect(Connection *const conn);

    static void *new_thread(void *);

public:
    static OnionRoutingApp &create_app(const std::string &pubkey_file, const std::string &privkey_file);

    int join_network(const std::string &netfile);
    int handle_client(int clientsock);

    const std::string get_address() const { return this->address; }
};

#endif