#include <string.h>
#include <thread>

#include "./client.hh"

#include "../util/debug.hh"

using namespace std;

Client::Client(const string &pubkeyfile, const string &privkeyfile)
{
    this->pubkeyPEM = (PLAINTEXT)readFile(pubkeyfile, "rb");

    this->server = 0;
    this->clientSocket = new Socket();

    KEY_UTIL::getKeyHexDigest(this->pubkeyPEM, this->hexaddress);

    this->initCryptoContext(privkeyfile);
}

Client::~Client()
{
    std::map<std::string, NetworkNode *>::iterator it = networkNodes.begin();
    std::map<std::string, NetworkNode *>::iterator it_end = networkNodes.end();

    for (; it != it_end; it++)
    {
        if (it->second != this->server)
        {
            delete it->second;
        }
    }

    delete this->clientSocket;
    delete this->server;

    this->clientSocket = 0;
    this->server = 0;
}

int Client::initCryptoContext(const string &privkeyfile)
{
    if (this->cryptoContext.rsaInitPrivkeyFile(privkeyfile) < 0)
    {
        return -1;
    }

    if (this->cryptoContext.rsaInitDecryption() < 0)
    {
        return -1;
    }

    if (this->cryptoContext.rsaInitSignature() < 0)
    {
        return -1;
    }

    if (this->cryptoContext.aesInit() < 0)
    {
        return -1;
    }

    return 0;
}

int Client::setupSessionFromIncomingHandshake(MessageParser &mp, CryptoContext *cryptoContext, std::map<std::string, NetworkNode *> *routes)
{
    NetworkNode *newroute = new NetworkNode;

    newroute->aesctxDuplicate(cryptoContext);

    if (mp.handshake(cryptoContext->getRSA(), newroute->getAES()) < 0)
    {
        return -1;
    }

    mp.removeId();

    routes->insert(pair<string, NetworkNode *>(mp.getParsedId(), newroute));

    return 0;
}

int Client::exitSignal(MessageParser &mp, std::map<string, NetworkNode *> *routes)
{
    mp.removeId();
    const string &session_id = mp.getParsedId();

    NetworkNode *route = (*routes)[session_id];

    if (not route)
    {
        return -1;
    }

    delete route;
    route = 0;

    routes->erase(session_id);

    return 0;
}

int Client::decryptIncomingMessage(MessageParser &mp, map<string, NetworkNode *> *routes)
{
    mp.removeId();
    NetworkNode *route = (*routes)[mp.getParsedId()];

    if ((not route or mp.decrypt(route) < 0))
    {
        return -1;
    }

    mp.removeNext();

    return 0;
}

int Client::action(MessageParser &mp, CryptoContext *cryptoContext, map<string, NetworkNode *> *routes)
{
    if (mp.isHandshake())
    {
        if (setupSessionFromIncomingHandshake(mp, cryptoContext, routes) < 0)
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
    ClientListenerContext *clientListenerData = (ClientListenerContext *)args;

    Socket *clientSocket = clientListenerData->clientSocket;

    map<string, NetworkNode *> *networkNodes = clientListenerData->networkNodes;

    CryptoContext *cryptoContext = clientListenerData->cryptoContext;

    string nextAddress;

    MessageParser mp;

    IncomingMessageCallback incomingMessageCallback = clientListenerData->incomingMessageCallback;

    while (clientSocket->readNetworkData(mp) > 0)
    {
        NEWLINE();

        if (action(mp, cryptoContext, networkNodes) == 0)
        {
            mp.clear();
            continue;
        }

        if (decryptIncomingMessage(mp, networkNodes) < 0)
        {
            mp.clear();
            continue;
        }

        if (incomingMessageCallback)
        {
            incomingMessageCallback(mp);
        }

        mp.clear();
    }

    return 0;
}

int Client::setupSocket(const std::string &host, const std::string &port)
{
    if (this->clientSocket->isConnected())
    {
        this->clientSocket->closeSocket();
    }

    this->clientSocket->createConnection(host, port);

    if (not this->clientSocket->isConnected())
    {
        return -1;
    }

    return 0;
}

const string Client::setupNetworkNode(const string &keyfile, NetworkNode **route, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
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

    NetworkNode *newNetworkNode = new NetworkNode;

    newNetworkNode->aesctxDuplicate(&this->cryptoContext);

    if (newNetworkNode->pubkeyInit(pubkey) < 0)
    {
        return "";
    }

    if (newNetworkNode->aesctxInit(key, keylen) < 0)
    {
        return "";
    }

    newNetworkNode->setId(id);

    const CHAR *hexdigest = newNetworkNode->getPubkeyHexDigest();

    this->networkNodes[hexdigest] = newNetworkNode;

    if (route)
    {
        *route = newNetworkNode;
    }

    return newNetworkNode->getPubkeyHexDigest();
}

const string Client::addNode(const std::string &keyfile, const std::string &last_address, bool identify, bool make_new_session)
{
    NetworkNode *last_route = networkNodes[last_address];

    if (not last_route)
    {
        return "";
    }

    NetworkNode *new_route;
    string dest_address;

    if (make_new_session)
    {
        dest_address = this->setupNetworkNode(keyfile, &new_route);
    }
    else
    {
        dest_address = this->setupNetworkNode(keyfile, &new_route, 0, last_route->getId());
    }

    if (not new_route)
    {
        return "";
    }

    new_route->setPrevious(last_route);
    last_route->setNext(new_route);

    this->handshake(new_route, identify);

    return dest_address;
}

int Client::createConnection(const string &host, const string &port, const string &keyfile, bool start_listener)
{
    if (this->setupSocket(host, port) < 0)
    {
        return -1;
    }

    if (not this->clientSocket->isConnected())
    {
        ERROR("Could not open connection to ", host, ":", port);
        return -1;
    }

    string serv_address = this->setupNetworkNode(keyfile, &this->server);

    if (not this->server)
    {
        return -1;
    }

    if (this->handshake(this->server) < 0)
    {
        return -1;
    }

    //INFO("HANDSHAKE SENT");

    if (start_listener)
    {
        ClientListenerContext *clientListenerData = new ClientListenerContext;

        clientListenerData->networkNodes = &this->networkNodes;
        clientListenerData->clientSocket = this->clientSocket;
        clientListenerData->cryptoContext = &this->cryptoContext;
        clientListenerData->incomingMessageCallback = this->incomingMessageCallback;

        pthread_t new_thread;
        pthread_create(&new_thread, 0, this->dataListener, clientListenerData);
    }

    return 0;
}

int Client::writeDataWithEncryption(MessageBuilder &mb, NetworkNode *route)
{
    NetworkNode *p = route;

    if (mb.isHandshake())
    {
        // mb.set_id(p->get_id());
        p = p->getPrevious();
    }

    NetworkNode *next;

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

    return this->clientSocket->writeData(mb) < 0 ? -1 : 0;
}

int Client::handshake(NetworkNode *route, bool add_pubkey)
{
    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    if (add_pubkey)
    {
        mb.handshake(route, this->cryptoContext.getRSA(), this->pubkeyPEM);
    }
    else
    {
        mb.handshake(route);
    }

    return this->writeDataWithEncryption(mb, route) < 0 ? -1 : 0;
}

void Client::cleanupCircuit(NetworkNode *route)
{
    NetworkNode *next;
    for (NetworkNode *p = route->getPrevious(); p; p = p->getPrevious())
    {
        next = p->getNext();

        if (next)
        {
            this->networkNodes.erase(next->getPubkeyHexDigest());
            delete next;
            next = 0;
        }
    }
}

int Client::exitCircuit(const string &address)
{
    NetworkNode *route = this->networkNodes[address];

    if (not route)
    {
        return -1;
    }

    MessageBuilder mb;
    mb.exitCircuit();

    int result = this->writeDataWithEncryption(mb, route);

    this->cleanupCircuit(route);

    return result;
}

int Client::writeDataWithEncryption(const BYTE *data, SIZE datalen, const string &address)
{
    MessageBuilder mb(data, datalen);
    NetworkNode *route = this->networkNodes[address];

    if (not route)
    {
        return -1;
    }

    return this->writeDataWithEncryption(mb, route);
}
