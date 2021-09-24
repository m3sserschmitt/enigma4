#ifndef ONION_ROUTING_H
#define ONION_ROUTING_H

#include <cryptography/cryptography.hh>
#include <map>

#include "app.h"
#include "connection.hh"

class OnionRoutingApp : public App
{
    static const SIZE max_message_size = 4096;

    static std::map<std::string, Connection *> clients;

    static RSA_CRYPTO rsactx;
    static std::string address;

    OnionRoutingApp(const std::string &pubkey_file, const std::string &privkey_file);
    ~OnionRoutingApp();

    static int setup_session(MessageParser &mp, Connection *conn);
    static int try_handshake(MessageParser &mp, Connection *conn);
    static int forward_message(MessageParser &mp);

    static int redirect(Connection *const conn);
    // static int remove_client(Connection *conn, const CHAR *clientaddr);

    static void *new_thread(void *);

public:
    static OnionRoutingApp &get_handle(const std::string &pubkey_file, const std::string &privkey_file);

    int handle_client(int clientsock);

    const std::string get_address() const { return this->address; }
};

#endif