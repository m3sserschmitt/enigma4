#include "client.hh"

#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "util.hh"
#include "types.hh"
#include "message_builder.hh"
#include "message_parser.hh"

#include <cryptography/random.hh>
#include <cryptography/base64.hh>
#include <iostream>

using namespace std;

// pthread_mutex_t Client::mt;
// queue<string> Client::messages;

Client::Client(const string &pubkey, const string &privkey)
{
    this->pubkey = (PLAINTEXT)read_file(pubkey, "rb");
    this->serv = new route_t;
    this->sock = -1;

    get_key_hexdigest(this->pubkey, this->hexaddress);

    this->rsactx = CRYPTO::RSA_CRYPTO_new();
    CRYPTO::RSA_init_key_file(privkey, 0, 0, PRIVATE_KEY, this->rsactx);
    CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT);

    // pthread_mutex_init(&this->mt, 0);
}

int Client::decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, map<string, route_t *> *routes)
{
    mp.remove_id();
    route_t *route = (*routes)[mp["id"]];

    // try RSA decryption;
    if (not route)
    {
        if (mp.decrypt(rsactx) < 0)
        {
            return -1;
        }
    }
    else

    if (not route or mp.decrypt(route->aesctx) < 0)
    {
        return -1;
    }

    return 0;
}

void *Client::data_listener(void *args)
{
    listener_data *listener = (listener_data *)args;

    int sock = listener->sock;
    map<string, route_t *> *routes = listener->routes;
    RSA_CRYPTO rsactx = listener->rsactx;

    BYTES rawdata = new BYTE[Client::max_message_size];
    ssize_t recvlen;

    MessageParser mp;

    while ((recvlen = read(sock, rawdata, Client::max_message_size)) > 0)
    {
        cout << "\n[+] Data received: " << recvlen << " bytes.\n";
        mp.update(rawdata, recvlen);

        if(Client::decrypt_incoming_message(mp, rsactx, routes) < 0)
        {
            continue;
        }

        cout << "\nMessage: " << mp.get_data() << "\n";
        
    }

    return 0;
}

int Client::create_connection(const string &host, const string &port)
{
    struct sockaddr_in sock_addr;

    this->sock = socket(AF_INET, SOCK_STREAM, 0);

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(atoi(port.c_str()));
    sock_addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (connect(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
    {
        return -1;
    }

    listener_data *listener = new listener_data;
    listener->routes = &this->routes;
    listener->sock = this->sock;
    listener->rsactx = this->rsactx;

    pthread_t new_thread;
    pthread_create(&new_thread, 0, this->data_listener, listener);

    return 0;
}

int Client::init_aes(AES_CRYPTO ctx, const BYTE *key, SIZE keylen)
{
    BYTES _key = 0;
    BYTES _salt = 0;

    int ret = 0;

    if (CRYPTO::rand_bytes(32, &_key) < 0)
    {
        ret = -1;
        goto __end;
    }

    if (CRYPTO::rand_bytes(8, &_salt) < 0)
    {
        ret = -1;
        goto __end;
    }

    if (CRYPTO::AES_init(_key, 32, _salt, 10000, ctx) < 0)
    {
        ret = -1;
    }

    if (key and keylen)
    {
        CRYPTO::AES_setup_key(key, keylen, ctx);
    }

__end:
    delete[] _key;
    delete[] _salt;

    return ret;
}

int Client::setup_server(const std::string &keyfile)
{
    this->serv->aesctx = CRYPTO::AES_CRYPTO_new();
    this->serv->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)read_file(keyfile, "rb");

    if (not key)
    {
        return -1;
    }

    if (CRYPTO::RSA_init_key(key, 0, 0, PUBLIC_KEY, this->serv->rsactx) < 0)
    {
        return -1;
    }

    if (CRYPTO::RSA_init_ctx(this->serv->rsactx, ENCRYPT) < 0)
    {
        return -1;
    }

    if (this->init_aes(this->serv->aesctx) < 0)
    {
        return -1;
    }

    this->serv->keydigest = 0;
    get_keydigest(key, &this->serv->keydigest);

    route_t *dummy_next = new route_t;
    this->serv->next = dummy_next;

    return 0;
}

const string Client::setup_dest(const string &keyfile, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
{
    AES_CRYPTO dest_aesctx = CRYPTO::AES_CRYPTO_new();
    RSA_CRYPTO dest_rsactx = CRYPTO::RSA_CRYPTO_new();

    if (CRYPTO::AES_ctx_dup(dest_aesctx, this->serv->aesctx) < 0)
    {
        return "";
    }

    PLAINTEXT pubkey = (PLAINTEXT)read_file(keyfile, "rb");

    if (not pubkey)
    {
        return "";
    }

    if (CRYPTO::RSA_init_key(pubkey, 0, 0, PUBLIC_KEY, dest_rsactx) < 0)
    {
        return "";
    }

    if (CRYPTO::RSA_init_ctx(dest_rsactx, ENCRYPT) < 0)
    {
        return "";
    }

    if (this->init_aes(dest_aesctx, key, keylen) < 0)
    {
        return "";
    }

    route_t *route = new route_t;
    route->aesctx = dest_aesctx;
    route->rsactx = dest_rsactx;
    route->next = 0;

    route->keydigest = 0;
    get_keydigest(pubkey, &route->keydigest);

    PLAINTEXT hexaddr = 0;
    CRYPTO::hex(route->keydigest, 32, &hexaddr);
    this->routes[hexaddr] = route;

    BASE64 session_id = 0;
    if (id)
    {
        route->id = new BYTE[16 + 1];
        memcpy(route->id, id, 16);
    }
    else
    {
        CRYPTO::rand_bytes(16, &route->id);
    }

    CRYPTO::base64_encode(route->id, 16, &session_id);
    this->routes[session_id] = route;

    string address = hexaddr;
    delete[] hexaddr;

    return address;
}

int Client::get_base64_dest_key(route_t *route, BASE64 *key) const
{
    BYTES rawkey = 0;
    int ret = 0;

    if (CRYPTO::AES_read_key(route->aesctx, 32, &rawkey) < 0)
    {
        delete[] rawkey;
        return -1;
    }

    if (CRYPTO::base64_encode(rawkey, 32, key) < 0)
    {
        delete[] rawkey;
        return -1;
    }

    return 0;
}

int Client::write_serv(MessageBuilder &mb, route_t *route, bool rsa)
{
    if (rsa and mb.encrypt(this->serv->rsactx) < 0)
    {
        return -1;
    }
    else if (not rsa)
    {
        // if (not route->next)
        // {
        mb.set_id(route->id);
        // }
        mb.set_next(route->keydigest);

        if (mb.encrypt(this->serv->aesctx) < 0)
        {
            return -1;
        }
    }

    return write(this->sock, mb.get_data(), mb.get_datalen());
}

int Client::write_dest(MessageBuilder &mb, route_t *route, bool rsa)
{
    if (rsa and mb.encrypt(route->rsactx) < 0)
    {
        return -1;
    }
    else if (not rsa and mb.encrypt(route->aesctx) < 0)
    {
        return -1;
    }

    return this->write_serv(mb, route);
}

int Client::handshake()
{
    BASE64 enckey = new CHAR[64 + 1];

    if (this->get_base64_dest_key(this->serv, &enckey) < 0)
    {
        delete enckey;
        return -1;
    }

    MessageBuilder mb("pass: " + string(enckey));
    delete enckey;

    if (this->write_serv(mb, this->serv, 1) < 0)
    {
        return -1;
    }

    mb.update("pubkey: " + this->pubkey);

    return this->write_serv(mb, this->serv);
}

int Client::send_dest_key(const string &address)
{
    BASE64 key = 0;
    route_t *route = this->routes[address];

    this->get_base64_dest_key(route, &key);

    MessageBuilder mb("pass: " + string(key));
    mb.enable_next(1);

    return this->write_dest(mb, route, 1);
}

int Client::write_data(const BYTE *data, SIZE datalen, const string &address)
{
    MessageBuilder mb(data, datalen);
    route_t *route = this->routes[address];
    mb.enable_next(1);

    if (not route)
    {
        return -1;
    }

    return this->write_dest(mb, route);
}
