#ifndef ONION_ROUTING_H
#define ONION_ROUTING_H

#include <cryptography/cryptography.hh>
#include <map>

#include "app.h"
#include "types.hh"

class OnionRoutingApp : public App
{
    static const SIZE max_message_size = 4096;

    static std::map<std::string, connection_t *> clients;

    static RSA_CRYPTO rsactx;
    static std::string address;

    OnionRoutingApp(const std::string &pubkey_file, const std::string &privkey_file);
    ~OnionRoutingApp();

    static int setup_session_key(MessageParser &mp, connection_t *conn);
    static int setup_session_pkey(MessageParser &mp, connection_t *conn);

    static int handshake(connection_t *const conn);
    static const CHAR *insert_client(connection_t *const conn);
    static int redirect(connection_t *const conn);
    static int remove_client(connection_t *conn, const CHAR *clientaddr);

    static void *new_thread(void *);

public:
    static OnionRoutingApp &get_handle(const std::string &pubkey_file, const std::string &privkey_file);

    int handle_client(int clientsock);

    const std::string get_address() const { return this->address; }
};

#endif