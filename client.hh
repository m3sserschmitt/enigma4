#ifndef CLIENT_HH
#define CLIENT_HH

#include "message_builder.hh"
#include "message_parser.hh"

#include <cryptography/cryptography.hh>
#include <cryptography/random.hh>

#include <map>
#include <string>
#include <queue>
#include "socket.hh"
#include "util.hh"
#include "route.hh"

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

    int handshake(Route *route);
    int handshake(const std::string &address);

    static int setup_session_from_handshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx);
    static int action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, std::map<std::string, Route *> *routes);

    static int decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes);
    static void *data_listener(void *node);

    int write_dest(MessageBuilder &mb, Route *route, bool f = 1);

    Client(const Client &c);
    const Client &operator=(const Client &c);

public:
    Client(const std::string &pubkey, const std::string &privkey);

    const std::string &get_client_hexaddress() const { return this->hexaddress; }
    const std::string get_server_address() const { return this->serv->get_key_hexdigest(); }

    int create_connection(const std::string &host, const std::string &port, const std::string &keyfile);

    const std::string add_node(const std::string &keyfile, const std::string &last_address);

    int write_data(const BYTE *data, SIZE datalen, const std::string &address);

    int exit_circuit(const std::string &address);

    Socket *get_socket() { return this->sock; }
    void set_socket(Socket *s) { this->sock = s; }
};

#endif