#ifndef CLIENT_HH
#define CLIENT_HH

#include <cryptography/cryptography.hh>

#include "../protocol/message_builder.hh"
#include "../protocol/message_parser.hh"

#include "../onion_routing/connection.hh"

#include "route.hh"

#include "../networking/socket.hh"

class Client
{
    struct listener_data
    {
        Socket *sock;
        RSA_CRYPTO rsactx;
        AES_CRYPTO aesctx;
        std::string client_address;
        std::map<std::string, Route *> *routes;
    };

    Socket *sock;
    Route *serv;

    std::map<std::string, Route *> routes;

    std::string pubkey;
    std::string hexaddress;

    RSA_CRYPTO rsactx;

    virtual int setup_socket(const std::string &host, const std::string &port);

    const std::string setup_dest(const std::string &keyfile, Route **route, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    int handshake(Route *route, bool add_pubkey = true);

    static int setup_session_from_handshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx);
    static int action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, std::map<std::string, Route *> *routes);

    static int decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes);
    static void *data_listener(void *node);

    int write_dest(MessageBuilder &mb, Route *route);

    Client(const Client &c);
    const Client &operator=(const Client &c);

public:
    Client(const std::string &pubkey, const std::string &privkey);
    ~Client()
    {
        delete this->sock;
        delete this->serv;

        CRYPTO::RSA_CRYPTO_free(this->rsactx);

        this->sock = 0;
        this->serv = 0;
        this->rsactx = 0;
    }

    const std::string &get_client_hexaddress() const { return this->hexaddress; }
    const std::string get_server_address() const { return this->serv->get_key_hexdigest(); }

    int create_connection(const std::string &host, const std::string &port, const std::string &keyfile, bool start_listener = true);

    const std::string add_node(const std::string &keyfile, const std::string &last_address, bool identify = false, bool make_new_session = false);

    int write_data(const BYTE *data, SIZE datalen, const std::string &address);

    int exit_circuit(const std::string &address);

    Socket *get_socket() { return this->sock; }
    void set_socket(Socket *s) { this->sock = s; }

    Connection *make_connection() const
    {
        Socket *new_socket = sock->make_socket_copy();
        Connection *new_connection = new Connection(new_socket);

        new_connection->set_address(this->get_server_address());

        return new_connection;
    }
};

#endif