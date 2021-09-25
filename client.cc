#include "client.hh"

#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "util.hh"
#include "connection.hh"
#include "message_builder.hh"
#include "message_parser.hh"
#include "tls_socket.hh"

#include <cryptography/random.hh>
#include <cryptography/base64.hh>
#include <iostream>
#include "debug.hh"

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
    this->serv = 0;
    this->sock = 0;

    KEY_UTIL::get_key_hexdigest(this->pubkey, this->hexaddress);

    this->rsactx = CRYPTO::RSA_CRYPTO_new();
    CRYPTO::RSA_init_key_file(privkey, 0, 0, PRIVATE_KEY, this->rsactx);
    CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT);
}

int Client::setup_session_from_handshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx)
{
    Route *newroute = new Route;

    newroute->aesctx_dup(aesctx);

    if (mp.handshake(rsactx, newroute->get_aesctx()) < 0)
    {
        return -1;
    }

    routes->insert(pair<string, Route *>(mp["id"], newroute));

    return 0;
}

int Client::decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, map<string, Route *> *routes)
{
    mp.remove_id();
    Route *route = (*routes)[mp["id"]];

    INFO("Session ID: " << mp["id"]);

    if ((not route or mp.decrypt(route->get_aesctx()) < 0))
    {
        return -1;
    }

    mp.remove_next();

    return 0;
}

void *Client::data_listener(void *args)
{
    listener_data *listener = (listener_data *)args;

    Socket *sock = listener->sock;
    map<string, Route *> *routes = listener->routes;
    RSA_CRYPTO rsactx = listener->rsactx;
    AES_CRYPTO aesctx = listener->aesctx;

    MessageParser mp;

    while (sock->read_data(mp) > 0)
    {
        NEWLINE();
        INFO("Data received: " << mp.get_datalen() << " bytes.");

        if (mp.is_handshake())
        {
            NEWLINE();
            INFO("Handshake received.");

            if (setup_session_from_handshake(mp, rsactx, routes, aesctx) < 0)
            {
                FAILED("Handshake failed.");
                continue;
            }

            INFO("Handshake completed.");
            INFO("Session ID: " << mp["id"]);

            continue;
        }

        if (decrypt_incoming_message(mp, rsactx, routes) < 0)
        {
            continue;
        }

        INFO("Destination: " << mp["next"]);
        NEWLINE();
        INFO("Message content: " << mp.get_payload());

        cout << mp.get_payload();
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

const string Client::setup_dest(const string &keyfile, Route **route, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
{
    PLAINTEXT pubkey = (PLAINTEXT)read_file(keyfile, "rb");

    if (route)
    {
        *route = 0;
    }

    if (not pubkey)
    {
        return "";
    }

    Route *dest_route = new Route;

    if (this->serv and dest_route->aesctx_dup(this->serv) < 0)
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

    if (this->serv)
    {
        if (dest_route->set_id(this->serv->get_id()) < 0)
        {
            return "";
        }
    }
    else
    {
        dest_route->set_id(id);
    }

    const CHAR *hexdigest = dest_route->get_key_hexdigest();
    // const CHAR *base64id = dest_route->encode_id();

    this->routes[hexdigest] = dest_route;
    // this->routes[base64id] = dest_route;

    if (route)
    {
        *route = dest_route;
    }

    // delete[] base64id;
    return dest_route->get_key_hexdigest();
}

const string Client::add_node(const std::string &keyfile, const std::string &last_address)
{
    Route *last_route = routes[last_address];

    if (not last_route)
    {
        return "";
    }

    Route *new_route;
    string dest_address = this->setup_dest(keyfile, &new_route);

    if (not new_route)
    {
        return "";
    }

    new_route->set_previous(last_route);
    last_route->set_next(new_route);

    this->handshake(new_route);

    return dest_address;
}

int Client::create_connection(const string &host, const string &port, const string &keyfile)
{
    if (this->setup_socket(host, port) < 0)
    {
        return -1;
    }

    string serv_address = this->setup_dest(keyfile, &this->serv);

    if (not this->serv)
    {
        return -1;
    }

    if (this->handshake(this->serv) < 0)
    {
        return -1;
    }

    listener_data *listener = new listener_data;

    listener->routes = &this->routes;
    listener->sock = this->sock;
    listener->rsactx = this->rsactx;
    listener->aesctx = this->serv->get_aesctx();

    pthread_t new_thread;
    pthread_create(&new_thread, 0, this->data_listener, listener);

    return 0;
}

int Client::write_dest(MessageBuilder &mb, Route *route, bool first)
{
    if (not route)
    {
        return this->sock->write_data(mb);
    }
    else
    {
        AES_CRYPTO aesctx = route->get_aesctx();

        if (not CRYPTO::AES_encrypt_ready(aesctx))
        {
            return -1;
        }

        bool is_handshake = mb.is_handshake() and first;

        if (not is_handshake)
        {
            Route *dest = route->get_next() ? route->get_next() : route;

            mb.set_next(dest->get_keydigest());

            if (mb.encrypt(route->get_aesctx()) < 0)
            {
                return -1;
            }
        }

        mb.set_id(route->get_id());

        return this->write_dest(mb, route->get_previous(), 0);
    }
}

int Client::handshake(Route *route)
{
    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    mb.handshake(route->get_aesctx(), route->get_rsactx(), this->pubkey);

    return this->write_dest(mb, route) > 0 ? 0 : -1;
}

int Client::handshake(const string &dest)
{
    return this->handshake(routes[dest]);
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
