#ifndef CLIENT_HH
#define CLIENT_HH

#include "message_builder.hh"
#include "message_parser.hh"

#include <cryptography/aes.hh>
#include <cryptography/rsa.hh>

#include <map>
#include <string>
#include <queue>

class Client
{
    struct route_t
    {
        AES_CRYPTO aesctx;
        RSA_CRYPTO rsactx;
        BYTES keydigest;
        BYTES id;
        route_t *next;
    };

    struct listener_data
    {
        int sock;
        std::map<std::string, route_t *> *routes;
        RSA_CRYPTO rsactx;
        
    };

    static const SIZE max_message_size = 4096;

    int sock;
    route_t *serv;

    std::map<std::string, route_t *> routes;

    std::string pubkey;
    std::string hexaddress;

    RSA_CRYPTO rsactx;

    int init_aes(AES_CRYPTO ctx, const BYTE *key = 0, SIZE keylen = 32);

    int write_serv(MessageBuilder &mb, route_t *route, bool rsa = false);
    int write_dest(MessageBuilder &mb, route_t *route, bool rsa = false);

    static int decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, route_t *> *routes);
    static void *data_listener(void *node);
    int get_base64_dest_key(route_t *route, BASE64 *key) const;

public:
    Client(const std::string &pubkey, const std::string &privkey);

    const std::string &get_client_hexaddress() { return this->hexaddress; }

    int setup_server(const std::string &keyfile);
    const std::string setup_dest(const std::string &keyfile, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    int create_connection(const std::string &host, const std::string &port);

    int handshake();
    int send_dest_key(const std::string &address);

    int write_data(const BYTE *data, SIZE datalen, const std::string &address);
};

#endif