#include <string.h>

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

    if (CRYPTO::RSA_init_key_file(privkey, 0, 0, PRIVATE_KEY, this->rsactx) < 0)
    {
        FAILURE("Client Private Key initialization failed.");
    }

    if (CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT) < 0)
    {
        FAILURE("Client Private Key decryption initialization failed.")
    }

    if (CRYPTO::RSA_init_ctx(this->rsactx, SIGN) < 0)
    {
        FAILURE("Client Private Key signing initialization failed.");
    }
}

Client::~Client()
{
    std::map<std::string, Route *>::iterator it = routes.begin();
    std::map<std::string, Route *>::iterator it_end = routes.end();

    for (; it != it_end; it++)
    {
        if (it->second != this->serv)
        {
            delete it->second;
        }
    }

    delete this->sock;
    delete this->serv;

    CRYPTO::RSA_CRYPTO_free(this->rsactx);

    this->sock = 0;
    this->serv = 0;
    this->rsactx = 0;
}

int Client::setup_session_from_handshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx)
{
    Route *newroute = new Route;

    newroute->aesctx_dup(aesctx);

    if (mp.handshake(rsactx, newroute->get_aesctx()) < 0)
    {
        return -1;
    }

    mp.remove_id();

    routes->insert(pair<string, Route *>(mp.get_parsed_id(), newroute));

    return 0;
}

int Client::exit_signal(MessageParser &mp, std::map<string, Route *> *routes)
{
    mp.remove_id();
    const string &session_id = mp.get_parsed_id();

    Route *route = (*routes)[session_id];

    if (not route)
    {
        return -1;
    }

    delete route;
    route = 0;

    routes->erase(session_id);

    return 0;
}

int Client::decrypt_incoming_message(MessageParser &mp, RSA_CRYPTO rsactx, map<string, Route *> *routes)
{
    mp.remove_id();
    Route *route = (*routes)[mp.get_parsed_id()];

    if ((not route or mp.decrypt(route) < 0))
    {
        return -1;
    }

    mp.remove_next();

    return 0;
}

int Client::action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, map<string, Route *> *routes)
{
    if (mp.is_handshake())
    {
        if (setup_session_from_handshake(mp, rsactx, routes, aesctx) < 0)
        {
            return -1;
        }

        INFO("Handshake completed for session ID: ", mp.get_parsed_id());

        return 0;
    }
    else if (mp.is_exit())
    {
        if (exit_signal(mp, routes) < 0)
        {
            return -1;
        }

        INFO("Session with ID ", mp.get_parsed_id(), " erased.");

        return 0;
    }

    return 1;
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

    while (sock->read_network_data(mp) > 0)
    {
        NEWLINE();

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

        if(mp.get_parsed_next_address() != client_address)
        {
            WARNING("Incoming message destination don't match local address.");
        }

        INFO("Message received; message content: ", mp.get_payload());

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

    dest_route->set_id(id);

    const CHAR *hexdigest = dest_route->get_pubkey_hexdigest();

    this->routes[hexdigest] = dest_route;

    if (route)
    {
        *route = dest_route;
    }

    return dest_route->get_pubkey_hexdigest();
}

const string Client::add_node(const std::string &keyfile, const std::string &last_address, bool identify, bool add_keys, bool make_new_session)
{
    Route *last_route = routes[last_address];

    if (not last_route)
    {
        return "";
    }

    Route *new_route;
    string dest_address;

    if (make_new_session)
    {
        dest_address = this->setup_dest(keyfile, &new_route);
    }
    else
    {
        dest_address = this->setup_dest(keyfile, &new_route, 0, last_route->get_id());
    }

    if (not new_route)
    {
        return "";
    }

    new_route->set_previous(last_route);
    last_route->set_next(new_route);

    this->handshake(new_route, identify, add_keys);

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

int Client::write_dest(MessageBuilder &mb, Route *route)
{
    Route *p = route;

    if (mb.is_handshake())
    {
        // mb.set_id(p->get_id());
        p = p->get_previous();
    }

    Route *next;

    for (; p; p = p->get_previous())
    {
        next = p->get_next();
        mb.set_next((next ? next : p)->get_pubkeydigest());

        if (mb.encrypt(p) < 0)
        {
            return -1;
        }

        mb.set_id(p->get_id());
    }

    return this->sock->write_data(mb) < 0 ? -1 : 0;
}

int Client::handshake(Route *route, bool add_pubkey, bool add_all_keys)
{
    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    if (add_pubkey)
    {
        mb.handshake(route, this->rsactx, this->pubkey, add_all_keys);
    }
    else
    {
        mb.handshake(route);
    }

    return this->write_dest(mb, route) < 0 ? -1 : 0;
}

void Client::cleanup_circuit(Route *route)
{
    Route *next;
    for (Route *p = route->get_previous(); p; p = p->get_previous())
    {
        next = p->get_next();

        if (next)
        {
            this->routes.erase(next->get_pubkey_hexdigest());
            delete next;
            next = 0;
        }
    }
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

    int result = this->write_dest(mb, route);

    this->cleanup_circuit(route);

    return result;
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
