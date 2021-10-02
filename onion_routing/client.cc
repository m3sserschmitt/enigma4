#include <string.h>

#include <cryptography/random.hh>
#include <cryptography/base64.hh>

#include "./client.hh"

#include "../util/debug.hh"

using namespace std;

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

    routes->insert(pair<string, Route *>(mp.get_parsed_id(), newroute));

    return 0;
}

int Client::decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, map<string, Route *> *routes)
{
    mp.remove_id();
    Route *route = (*routes)[mp.get_parsed_id()];

    INFO("Session ID: ", mp.get_parsed_id());

    if ((not route or mp.decrypt(route) < 0))
    {
        return -1;
    }

    mp.remove_next();

    return 0;
}

int Client::action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, map<string, Route *> *routes)
{
    mp.remove_id();
    const string &session_id = mp.get_parsed_id();

    if (mp.is_handshake())
    {
        NEWLINE();
        INFO("Handshake received for session ID: ", session_id);

        if (setup_session_from_handshake(mp, rsactx, routes, aesctx) < 0)
        {
            FAILURE("Handshake failed for session ID: ", session_id);
            return 0;
        }

        INFO("Handshake completed for session ID: ", session_id);

        return 0;
    }
    else if (mp.is_exit())
    {
        INFO("EXIT received for session ID: ", session_id);

        Route *route = (*routes)[session_id];
        delete route;

        routes->erase(session_id);

        INFO("Session with ID ", session_id, " erased.");

        return 0;
    }

    return -1;
}

void *Client::data_listener(void *args)
{
    listener_data *listener = (listener_data *)args;

    Socket *sock = listener->sock;

    map<string, Route *> *routes = listener->routes;

    RSA_CRYPTO rsactx = listener->rsactx;
    AES_CRYPTO aesctx = listener->aesctx;

    string client_address = listener->client_address;
    string next_address;

    MessageParser mp;

    while (sock->read_data(mp) > 0)
    {
        NEWLINE();

        mp.remove_id();
        INFO("Data received; session ID: ", mp.get_parsed_id());
    

        if (action(mp, rsactx, aesctx, routes) == 0)
        {
            mp.clear();
            continue;
        }

        if (decrypt_incoming_message(mp, rsactx, routes) < 0)
        {
            mp.clear();
            continue;
        }

        next_address = mp.get_parsed_next_address();

        INFO("Destination: ", next_address, (next_address == client_address ? " -> Match!" : " -> Don't match !!"));
        INFO("Message content: ", mp.get_payload());

        mp.clear();
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

    if (not this->sock->is_connected())
    {
        return -1;
    }

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

int Client::create_connection(const string &host, const string &port, const string &keyfile, bool start_listener)
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

    if (start_listener)
    {
        listener_data *listener = new listener_data;

        listener->routes = &this->routes;
        listener->sock = this->sock;
        listener->rsactx = this->rsactx;
        listener->aesctx = this->serv->get_aesctx();
        listener->client_address = this->hexaddress;

        pthread_t new_thread;
        pthread_create(&new_thread, 0, this->data_listener, listener);
    }

    return 0;
}

int Client::write_dest(MessageBuilder &mb, Route *route, bool first)
{
    Route *p = route;

    if (mb.is_handshake())
    {
        mb.set_id(p->get_id());
        p = p->get_previous();
    }

    Route *next;

    for (; p; p = p->get_previous())
    {
        next = p->get_next();
        mb.set_next((next ? next : p)->get_keydigest());

        if (mb.encrypt(p->get_aesctx()) < 0)
        {
            return -1;
        }

        mb.set_id(p->get_id());
    }

    return this->sock->write_data(mb) < 0 ? -1 : 0;
}

int Client::handshake(Route *route)
{
    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    if (route != this->serv)
    {
        mb.handshake(route->get_aesctx(), route->get_rsactx(), "");
    }
    else
    {
        mb.handshake(route->get_aesctx(), route->get_rsactx(), this->pubkey);
    }

    return this->write_dest(mb, route) < 0 ? -1 : 0;
}

int Client::exit_circuit(const string &address)
{
    Route *route = this->routes[address];

    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    mb.exit_circuit();

    return this->write_dest(mb, route);
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
