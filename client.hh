#ifndef CLIENT_HH
#define CLIENT_HH

#include "message_builder.hh"

#include <cryptography/aes.hh>
#include <cryptography/rsa.hh>

#include <string>
#include <queue>

class Client
{
    static const SIZE max_message_size = 4096;
    
    int sock;

    static void *data_listener(void *node);
    static std::queue<std::string> messages;
    static pthread_mutex_t mt;

    std::string pubkey;

    AES_CRYPTO serv_aesctx;
    AES_CRYPTO dest_aesctx;

    RSA_CRYPTO serv_rsactx;
    RSA_CRYPTO dest_rsactx;

    int init_aes(AES_CRYPTO ctx);
    
    int write_serv(MessageBuilder &mb, bool rsa = false);
    int write_dest(MessageBuilder &mb, bool rsa = false);
    
public:
    Client(std::string pubkey);

    int setup_server(std::string keyfile);
    int setup_dest(std::string keyfile);

    int get_base64_dest_key(BASE64 *key);

    int create_connection(std::string host, std::string port);
    
    int handshake();
    int setup_dest_key();

    int write_data(BYTES data, SIZE datalen);
};

#endif