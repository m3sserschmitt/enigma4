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
#include "tls_socket.hh"

#include <cryptography/random.hh>
#include <cryptography/base64.hh>
#include <iostream>

#include "message_const.hh"

using namespace std;

int Client::Route::aesctx_init(const BYTE *key, SIZE keylen)
{
    if (key and keylen)
    {
        return CRYPTO::AES_setup_key(key, keylen, this->aesctx);
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

        if (CRYPTO::AES_init(_key, 32, _salt, 100000, this->aesctx) < 0)
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

Client::Client(const string &pubkey, const string &privkey)
{
    this->pubkey = (PLAINTEXT)read_file(pubkey, "rb");
    this->serv = new Route;
    this->sock = 0;

    KEY_UTIL::get_key_hexdigest(this->pubkey, this->hexaddress);

    this->rsactx = CRYPTO::RSA_CRYPTO_new();
    CRYPTO::RSA_init_key_file(privkey, 0, 0, PRIVATE_KEY, this->rsactx);
    CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT);
}

int Client::decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, map<string, Route *> *routes)
{
    mp.remove_id();
    Route *route = (*routes)[mp["id"]];

    if (mp.decrypt(rsactx) < 0 and (not route or mp.decrypt(route->get_aesctx()) < 0))
    {
        return -1;
    }

    return 0;
}

void *Client::data_listener(void *args)
{
    listener_data *listener = (listener_data *)args;

    Socket *sock = listener->sock;
    map<string, Route *> *routes = listener->routes;
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

int Client::setup_socket(const std::string &host, const std::string &port)
{
    if (this->sock)
    {
        return -1;
    }

    this->sock = new Socket(host, port);
    return 0;
}

int Client::create_connection(const string &host, const string &port)
{
    if (this->setup_socket(host, port) < 0)
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

int Client::setup_server(const std::string &keyfile)
{
    PLAINTEXT pubkey = (PLAINTEXT)read_file(keyfile, "rb");

    if (not pubkey)
    {
        return -1;
    }

    if (this->serv->rsactx_init(pubkey) < 0)
    {
        return -1;
    }

    if (this->serv->aesctx_init() < 0)
    {
        return -1;
    }

    return 0;
}

const string Client::setup_dest(const string &keyfile, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
{
    PLAINTEXT pubkey = (PLAINTEXT)read_file(keyfile, "rb");

    if (not pubkey)
    {
        return "";
    }

    Route *dest_route = new Route;

    if (dest_route->aesctx_dup(this->serv) < 0)
    {
        return "";
    }

    if (dest_route->rsactx_init(pubkey) < 0)
    {
        return "";
    }

    if (dest_route->aesctx_init(key, keylen) < 0)
    {
        return "";
    }

    this->routes[dest_route->get_key_hexdigest()] = dest_route;

    if (id)
    {
        dest_route->set_id(id);
    }
    else if (dest_route->gen_id() < 0)
    {
        return "";
    }

    const CHAR *base64id = dest_route->encode_id();
    this->routes[base64id] = dest_route;
    delete[] base64id;

    return dest_route->get_key_hexdigest();
}

int Client::write_serv(MessageBuilder &mb, bool rsa)
{
    if (rsa and mb.encrypt(this->serv->get_rsactx()) < 0)
    {
        return -1;
    }
    else if (not rsa and mb.encrypt(this->serv->get_aesctx()) < 0)
    {
        return -1;
    }

    return this->sock->write_data(mb);
}

int Client::write_dest(MessageBuilder &mb, Route *route, bool rsa)
{
    if (rsa and mb.encrypt(route->get_rsactx()) < 0)
    {
        return -1;
    }
    else if (not rsa and mb.encrypt(route->get_aesctx()) < 0)
    {
        return -1;
    }

    mb.set_id(route->get_id());
    mb.set_next(route->get_keydigest());

    if (route->get_next())
    {
        route = route->get_next();
        return this->write_dest(mb, route);
    }

    return this->write_serv(mb);
}

int Client::handshake()
{
    const CHAR *base64key = this->serv->encode_key();
    MessageBuilder mb("pass: " + string(base64key));
    delete[] base64key;

    if (this->write_serv(mb, 1) < 0)
    {
        return -1;
    }

    mb.set_payload("pubkey: " + this->pubkey);

    return this->write_serv(mb) > 0 ? 0 : -1;
}

int Client::write_data(const BYTE *data, SIZE datalen, const string &address)
{
    MessageBuilder mb(data, datalen);
    Route *route = this->routes[address];

    if (not route)
    {
        return -1;
    }

    return this->write_dest(mb, route);
}
