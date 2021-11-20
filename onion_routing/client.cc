#include <string.h>
#include <thread>

#include "./client.hh"

#include "../util/debug.hh"

using namespace std;

Client::Client(const string &pubkey, const string &privkey)
{
    this->pubkey = (PLAINTEXT)readFile(pubkey, "rb");

    this->serv = 0;
    this->sock = 0;

    KEY_UTIL::getKeyHexDigest(this->pubkey, this->hexaddress);

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

int Client::setupSessionFromHandshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx)
{
    Route *newroute = new Route;

    newroute->aesctxDuplicate(aesctx);

    if (mp.handshake(rsactx, newroute->getAesctx()) < 0)
    {
        return -1;
    }

    mp.removeId();

    routes->insert(pair<string, Route *>(mp.getParsedId(), newroute));

    return 0;
}

int Client::exitSignal(MessageParser &mp, std::map<string, Route *> *routes)
{
    mp.removeId();
    const string &session_id = mp.getParsedId();

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

int Client::decryptIncomingMessage(MessageParser &mp, RSA_CRYPTO rsactx, map<string, Route *> *routes)
{
    mp.removeId();
    Route *route = (*routes)[mp.getParsedId()];

    if ((not route or mp.decrypt(route) < 0))
    {
        return -1;
    }

    mp.removeNext();

    return 0;
}

int Client::action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, map<string, Route *> *routes)
{
    if (mp.isHandshake())
    {
        if (setupSessionFromHandshake(mp, rsactx, routes, aesctx) < 0)
        {
            return -1;
        }

        INFO("Handshake completed for session ID: ", mp.getParsedId());

        return 0;
    }
    else if (mp.isExit())
    {
        if (exitSignal(mp, routes) < 0)
        {
            return -1;
        }

        INFO("Session with ID ", mp.getParsedId(), " erased.");

        return 0;
    }

    return 1;
}

void *Client::dataListener(void *args)
{
    listener_data *listener = (listener_data *)args;

    Socket *sock = listener->sock;

    map<string, Route *> *routes = listener->routes;

    RSA_CRYPTO rsactx = listener->rsactx;
    AES_CRYPTO aesctx = listener->aesctx;

    string client_address = listener->clientAddress;
    string next_address;

    MessageParser mp;

    while (sock->readNetworkData(mp) > 0)
    {
        NEWLINE();

        if (action(mp, rsactx, aesctx, routes) == 0)
        {
            mp.clear();
            continue;
        }

        if (decryptIncomingMessage(mp, rsactx, routes) < 0)
        {
            mp.clear();
            continue;
        }

        if(mp.getParsedNextAddress() != client_address)
        {
            WARNING("Incoming message destination don't match local address.");
        }

        INFO("Message received; message content: ", mp.getPayload());

        mp.clear();
    }

    return 0;
}

int Client::setupSocket(const std::string &host, const std::string &port)
{
    if (this->sock)
    {
        return -1;
    }

    this->sock = new Socket(host, port);

    if (not this->sock->isConnected())
    {
        return -1;
    }

    return 0;
}

const string Client::setupDest(const string &keyfile, Route **route, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
{
    PLAINTEXT pubkey = (PLAINTEXT)readFile(keyfile, "rb");

    if (route)
    {
        *route = 0;
    }

    if (not pubkey)
    {
        return "";
    }

    Route *dest_route = new Route;

    if (this->serv and dest_route->aesctxDuplicate(this->serv) < 0)
    {
        return "";
    }

    if (dest_route->rsactxInit(pubkey) < 0)
    {
        return "";
    }

    if (dest_route->aesctxInit(key, keylen) < 0)
    {
        return "";
    }

    dest_route->setId(id);

    const CHAR *hexdigest = dest_route->getPubkeyHexDigest();

    this->routes[hexdigest] = dest_route;

    if (route)
    {
        *route = dest_route;
    }

    return dest_route->getPubkeyHexDigest();
}

const string Client::addNode(const std::string &keyfile, const std::string &last_address, bool identify, bool add_keys, bool make_new_session)
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
        dest_address = this->setupDest(keyfile, &new_route);
    }
    else
    {
        dest_address = this->setupDest(keyfile, &new_route, 0, last_route->getId());
    }

    if (not new_route)
    {
        return "";
    }

    new_route->setPrevious(last_route);
    last_route->setNext(new_route);

    this->handshake(new_route, identify, add_keys);

    return dest_address;
}

int Client::createConnection(const string &host, const string &port, const string &keyfile, bool start_listener)
{
    if (this->setupSocket(host, port) < 0)
    {
        return -1;
    }

    //std::this_thread::sleep_for(std::chrono::milliseconds(200));

    string serv_address = this->setupDest(keyfile, &this->serv);

    if (not this->serv)
    {
        return -1;
    }

    
    if (this->handshake(this->serv) < 0)
    {
        return -1;
    }

    INFO("HANDSHAKE SENT");

    if (start_listener)
    {
        listener_data *listener = new listener_data;

        listener->routes = &this->routes;
        listener->sock = this->sock;
        listener->rsactx = this->rsactx;
        listener->aesctx = this->serv->getAesctx();
        listener->clientAddress = this->hexaddress;

        pthread_t new_thread;
        pthread_create(&new_thread, 0, this->dataListener, listener);
    }

    return 0;
}

int Client::writeDest(MessageBuilder &mb, Route *route)
{
    Route *p = route;

    if (mb.isHandshake())
    {
        // mb.set_id(p->get_id());
        p = p->getPrevious();
    }

    Route *next;

    for (; p; p = p->getPrevious())
    {
        next = p->getNext();
        mb.setNext((next ? next : p)->getPubkeydigest());

        if (mb.encrypt(p) < 0)
        {
            return -1;
        }

        mb.set_id(p->getId());
    }

    return this->sock->writeData(mb) < 0 ? -1 : 0;
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



    return this->writeDest(mb, route) < 0 ? -1 : 0;
}

void Client::cleanupCircuit(Route *route)
{
    Route *next;
    for (Route *p = route->getPrevious(); p; p = p->getPrevious())
    {
        next = p->getNext();

        if (next)
        {
            this->routes.erase(next->getPubkeyHexDigest());
            delete next;
            next = 0;
        }
    }
}

int Client::exitCircuit(const string &address)
{
    Route *route = this->routes[address];

    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    mb.exitCircuit();

    int result = this->writeDest(mb, route);

    this->cleanupCircuit(route);

    return result;
}

int Client::writeData(const BYTE *data, SIZE datalen, const string &address)
{
    MessageBuilder mb(data, datalen);
    Route *route = this->routes[address];

    if (not route)
    {
        return -1;
    }

    return this->writeDest(mb, route);
}
