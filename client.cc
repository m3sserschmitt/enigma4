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

#include "message_const.hh"

using namespace std;

Client::Client(const string &pubkey, const string &privkey)
{
    this->pubkey = (PLAINTEXT)read_file(pubkey, "rb");
    this->serv = new route_t;
    this->sock = new OSocket;

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

    if (mp.decrypt(rsactx) < 0 and (not route or mp.decrypt(route->aesctx) < 0))
    {
        return -1;
    }

    return 0;
}

void *Client::data_listener(void *args)
{
    listener_data *listener = (listener_data *)args;

    OSocket *sock = listener->sock;
    map<string, route_t *> *routes = listener->routes;
    RSA_CRYPTO rsactx = listener->rsactx;

    MessageParser mp;

    while (sock->read_data(mp) > 0)
    {
        cout << "\n[+] Data received: " << mp.get_datalen() << " bytes.\n";

        if (decrypt_incoming_message(mp, rsactx, routes) < 0)
        {
            continue;
        }

        cout << "\nMessage: " << mp.get_payload() << "\n";
    }

    return 0;
}

int Client::create_connection(const string &host, const string &port)
{
    int _sock;

    addrinfo addr_info;
    addr_info.ai_family = AF_INET;
    addr_info.ai_socktype = SOCK_STREAM;
    addr_info.ai_protocol = 0;
    addr_info.ai_flags = 0;

    addrinfo *res;
    addrinfo *p;

    if (getaddrinfo(host.c_str(), port.c_str(), &addr_info, &res) != 0)
    {
        return -1;
    }

    for (p = res; p != NULL; p = res->ai_next)
    {
        if((_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        {
            continue;
        }

        if (connect(_sock, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }

        close(_sock);
    }

    if(not p)
    {
        return -1;
    }

    this->sock->wrap(_sock);

    listener_data *listener = new listener_data;
    listener->routes = &this->routes;
    listener->sock = new OSocket(_sock);
    listener->rsactx = this->rsactx;

    pthread_t new_thread;
    pthread_create(&new_thread, 0, this->data_listener, listener);

    return 0;
}

int Client::init_aes(AES_CRYPTO ctx, const BYTE *key, SIZE keylen)
{
    CRYPTO::AES_iv_append(1, ctx);
    CRYPTO::AES_iv_autoset(1, ctx);

    if (key and keylen)
    {
        return CRYPTO::AES_setup_key(key, keylen, ctx);
    }
    else
    {
        BYTES _key = 0;
        BYTES _salt = 0;
        int ret = 0;

        if (CRYPTO::rand_bytes(32, &_key) < 0)
        {
            ret = -1;
            goto __end;
        }

        if (CRYPTO::rand_bytes(32, &_salt) < 0)
        {
            ret = -1;
            goto __end;
        }

        if (CRYPTO::AES_init(_key, 32, _salt, 100000, ctx) < 0)
        {
            ret = -1;
            goto __end;
        }

    __end:
        delete[] _key;
        delete[] _salt;

        return ret;
    }
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

    this->serv->next = 0;
    this->serv->keydigest = 0;
    get_keydigest(key, &this->serv->keydigest);

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

int Client::read_base64_key(route_t *route, BASE64 *key) const
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

int Client::write_serv(MessageBuilder &mb, bool rsa)
{
    if (rsa and mb.encrypt(this->serv->rsactx) < 0)
    {
        return -1;
    }
    else if (not rsa and mb.encrypt(this->serv->aesctx) < 0)
    {
        return -1;
    }

    return this->sock->write_data(mb);
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

    mb.set_id(route->id);
    mb.set_next(route->keydigest);

    if (route->next)
    {
        route = route->next;
        return this->write_dest(mb, route);
    }

    return this->write_serv(mb);
}

int Client::handshake()
{
    BASE64 enckey = new CHAR[64 + 1];

    if (this->read_base64_key(this->serv, &enckey) < 0)
    {
        delete[] enckey;
        return -1;
    }

    MessageBuilder mb("pass: " + string(enckey));
    delete[] enckey;

    if (this->write_serv(mb, 1) < 0)
    {
        return -1;
    }

    mb.set_payload("pubkey: " + this->pubkey);

    return this->write_serv(mb);
}

/*
int Client::send_dest_key(const string &address)
{
    BASE64 key = 0;
    route_t *route = this->routes[address];

    this->read_base64_key(route, &key);

    MessageBuilder mb("pass: " + string(key));
    // mb.enable_next(1);

    return this->write_dest(mb, route, 1);
}
*/

int Client::write_data(const BYTE *data, SIZE datalen, const string &address)
{
    MessageBuilder mb(data, datalen);
    route_t *route = this->routes[address];

    if (not route)
    {
        return -1;
    }

    return this->write_dest(mb, route);
}
