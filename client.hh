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

class Client
{
    class Route
    {
        AES_CRYPTO aesctx;
        RSA_CRYPTO rsactx;
        BYTES keydigest;
        PLAINTEXT key_hexdigest;
        BYTES id;
        Route *next;
        Route *previous;

    public:
        Route()
        {
            this->aesctx = CRYPTO::AES_CRYPTO_new();
            this->rsactx = CRYPTO::RSA_CRYPTO_new();

            CRYPTO::AES_iv_autoset(1, this->aesctx);
            CRYPTO::AES_iv_append(1, this->aesctx);

            this->next = 0;
            this->previous = 0;

            this->keydigest = new BYTE[32 + 1];
            this->key_hexdigest = new CHAR[64 + 1];
            this->id = new BYTE[16 + 1];

            memset(this->keydigest, 0, 32 + 1);
            memset(this->key_hexdigest, 0, 64 + 1);
            memset(this->id, 0, 16 + 1);
        }

        AES_CRYPTO get_aesctx() { return this->aesctx; }
        RSA_CRYPTO get_rsactx() { return this->rsactx; }

        int aesctx_dup(Route *route)
        {
            return CRYPTO::AES_ctx_dup(this->aesctx, route->aesctx);
        }
        int aesctx_dup(AES_CRYPTO ctx) 
        {
            return CRYPTO::AES_ctx_dup(this->aesctx, ctx);
        }

        int rsactx_init(const std::string &pubkey)
        {
            if (CRYPTO::RSA_init_key(pubkey, 0, 0, PUBLIC_KEY, this->rsactx) < 0)
            {
                return -1;
            }

            KEY_UTIL::get_keydigest(pubkey, &this->keydigest);
            CRYPTO::hex(this->keydigest, 32, &this->key_hexdigest);

            return CRYPTO::RSA_init_ctx(this->rsactx, ENCRYPT);
        }
        int aesctx_init(const BYTE *key = 0, SIZE keylen = 32);

        const CHAR *encode_key() const
        {
            BYTES key = 0;
            CRYPTO::AES_read_key(this->aesctx, 32, &key);

            BASE64 base64key = 0;
            CRYPTO::base64_encode(key, 32, &base64key);

            delete[] key;

            return base64key;
        }

        const BYTE *get_keydigest() const { return this->keydigest; }
        const CHAR *get_key_hexdigest() const { return this->key_hexdigest; }

        int set_id(const BYTE *id)
        {
            if (id)
            {
                memcpy(this->id, id, 16);
                return 0;
            }

            return CRYPTO::rand_bytes(16, &this->id) < 0 ? -1 : 0;
        }

        const CHAR *encode_id() const
        {
            BASE64 base64id = 0;
            CRYPTO::base64_encode(this->id, 16, &base64id);

            return base64id;
        }
        const BYTE *get_id() { return this->id; }

        void set_previous(Route *previous) { this->previous = previous; }
        Route *get_previous() { return this->previous; }

        void set_next(Route *next) {this->next = next;}
        Route *get_next() { return this->next; }
    };

    struct listener_data
    {
        Socket *sock;
        std::map<std::string, Route *> *routes;
        RSA_CRYPTO rsactx;
        AES_CRYPTO aesctx;
    };

    Socket *sock;
    Route *serv;

    std::map<std::string, Route *> routes;

    std::string pubkey;
    std::string hexaddress;

    RSA_CRYPTO rsactx;

    int handshake(Route *route);

    int write_dest(MessageBuilder &mb, Route *route, bool f = 1);

    static int setup_session_from_handshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx);
    static int decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes);
    static void *data_listener(void *node);

    virtual int setup_socket(const std::string &host, const std::string &port);
    const std::string setup_dest(const std::string &keyfile, Route **route, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    Client(const Client &c);
    const Client &operator=(const Client &c);

public:
    Client(const std::string &pubkey, const std::string &privkey);

    const std::string &get_client_hexaddress() const { return this->hexaddress; }

    int create_connection(const std::string &host, const std::string &port, const std::string &keyfile);
    int handshake(const std::string &address);

    const std::string get_server_address() const { return this->serv->get_key_hexdigest(); }

    const std::string add_node(const std::string &keyfile, const std::string &last_address);

    int write_data(const BYTE *data, SIZE datalen, const std::string &address);

    const Socket *get_socket() { return this->sock; }
    void set_socket(Socket *s) { this->sock = s; }
};

#endif