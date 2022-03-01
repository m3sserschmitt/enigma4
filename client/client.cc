#include <string.h>
#include <thread>

#include "client.hh"

#include "../util/debug.hh"

using namespace std;

Client::~Client()
{
    this->listenerStopWait();
    this->closeConnection();

    std::map<std::string, NetworkNode *>::iterator it = networkNodes.begin();
    std::map<std::string, NetworkNode *>::iterator it_end = networkNodes.end();

    // iterate over all NetworkNode structures and release memory
    for (; it != it_end; it++)
    {
        if (it->second != this->guardNode)
        {
            delete it->second;
            it->second = 0;
        }
    }

    delete this->guardNode;
    delete this->clientSocket;
    delete this->listenerContext;

    this->guardNode = 0;
    this->clientSocket = 0;
    this->listenerContext = 0;

    CRYPTO::RSA_CRYPTO_free(this->rsactx);
    CRYPTO::AES_CRYPTO_free(this->aesctx);
}

int Client::initCrypto(const string &privkeyfile)
{
    if (this->loadClientPrivateKey(privkeyfile) < 0)
    {
        return -1;
    }

    BYTES keyBuffer = 0;
    int ret = 0;

    if (CRYPTO::rand_bytes(AES_GCM_KEY_SIZE, &keyBuffer) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_setup_key(keyBuffer, AES_GCM_KEY_SIZE, this->aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_init_ctx(ENCRYPT, this->aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_init_ctx(DECRYPT, this->aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

cleanup:
    delete[] keyBuffer;
    keyBuffer = 0;

    return ret;
}

int Client::setupSessionFromIncomingHandshake(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, NodesMap *networkNodes)
{
    if (not mp.isAddSessionMessage())
    {
        return 1;
    }

    NetworkNode *newNode = new (nothrow) NetworkNode;

    if (not newNode or newNode->aesctxDuplicate(aesctx) < 0)
    {
        return -1;
    }

    int ret = 0;

    BYTES sessionId = 0;
    BYTES sessionKey = 0;

    if (mp.addSessionMessage(rsactx, &sessionId, &sessionKey) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    newNode->setId(sessionId);
    newNode->setSessionKey(sessionKey);

    networkNodes->insert(pair<string, NetworkNode *>(mp.getParsedId(), newNode));

cleanup:
    delete[] sessionId;
    delete[] sessionKey;

    sessionId = 0;
    sessionKey = 0;

    return 0;
}

int Client::exitSignal(MessageParser &mp, std::map<string, NetworkNode *> *routes)
{
    if (not mp.isExitSignal())
    {
        return 1;
    }

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

Client::MessageProcessingStatus Client::processIncomingMessage(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, NodesMap *networkNodes)
{
    switch (setupSessionFromIncomingHandshake(mp, rsactx, aesctx, networkNodes))
    {
    case -1:
        return PROCESSING_ERROR; // errors
    case 0:
        return SESSION_SET; // hanshake successful, no further actions required;
    }

    switch (decryptIncomingMessage(mp, networkNodes))
    {
    case -1:
    case 1:
        return DECRYPTION_FAILED;
    }

    switch (exitSignal(mp, networkNodes))
    {
    case -1:
        return PROCESSING_ERROR;
    case 0:
        return SESSION_CLEARED;
    }

    return MESSAGE_DECRYPTED_SUCCESSFULLY;
}

void *Client::dataListener(void *args)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);

    ClientListenerContext *clientListenerContext = (ClientListenerContext *)args;

    Socket *clientSocket = clientListenerContext->clientSocket;

    NodesMap *networkNodes = clientListenerContext->networkNodes;

    RSA_CRYPTO rsactx = clientListenerContext->rsactx;
    AES_CRYPTO aesctx = clientListenerContext->aesctx;

    OnMessageReceivedCallback messageReceivedCallback = clientListenerContext->messageReceivedCallback;

    OnNewSessionSetCallback newSessionSetCallback = clientListenerContext->newSessionSetCallback;

    OnSessionClearedCallback sessionClearedCallback = clientListenerContext->sessionClearedCallback;

    MessageParser &mp = clientListenerContext->mp;

    while (clientSocket->readData(mp) > 0)
    {
        MessageProcessingStatus status = processIncomingMessage(mp, rsactx, aesctx, networkNodes);

        if (status == MESSAGE_DECRYPTED_SUCCESSFULLY and messageReceivedCallback)
        {
            messageReceivedCallback(mp.getPayload(), mp.getPayloadSize(), mp.getParsedId().c_str(), "Guard Node", mp.getParsedNextAddress().c_str());
        }
        else if (status == SESSION_SET and newSessionSetCallback)
        {
            newSessionSetCallback(mp.getParsedId().c_str(), "Guard Node");
        } else if(status == SESSION_CLEARED and sessionClearedCallback)
        {
            sessionClearedCallback(mp.getParsedId().c_str(), "Guard Node");
        }

        mp.reset();
    }

    return 0;
}

int Client::connectSocket(const std::string &host, const std::string &port)
{
    if (not this->clientSocket)
    {
        this->makeSocket();
    }

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

    NetworkNode *newNetworkNode = new (nothrow) NetworkNode;

    newNetworkNode->aesctxDuplicate(this->aesctx);

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

const string Client::addNode(const std::string &keyfile, const std::string &lastAddress, bool newSessionId)
{
    NetworkNode *lastNode = networkNodes[lastAddress];

    if (not lastNode)
    {
        return "";
    }

    NetworkNode *newNode;
    string destinationAddress;

    if (newSessionId)
    {
        destinationAddress = this->setupNetworkNode(keyfile, &newNode);
    }
    else
    {
        destinationAddress = this->setupNetworkNode(keyfile, &newNode, 0, lastNode->getId());
    }

    if (not newNode)
    {
        return "";
    }

    newNode->setPrevious(lastNode);
    lastNode->setNext(newNode);

    this->addNewSession(newNode);

    return destinationAddress;
}

int Client::createConnection(const string &host, const string &port, const string &keyfile)
{
    if (this->connectSocket(host, port) < 0)
    {
        return -1;
    }

    if (not this->clientSocket->isConnected())
    {
        ERROR("Could not open connection to ", host, ":", port);
        return -1;
    }

    string serv_address = this->setupNetworkNode(keyfile, &this->guardNode);

    if (not this->guardNode)
    {
        return -1;
    }

    if (this->performGuardHandshake(this->guardNode) < 0)
    {
        return -1;
    }

    return 0;
}

int Client::startListener()
{
    if(not(this->listenerContext = new(nothrow) ClientListenerContext))
    {
        return -1;
    }

    if (not(this->listenerThread = new (nothrow) pthread_t))
    {
        return -1;
    }

    this->listenerContext->aesctx = this->aesctx;
    this->listenerContext->rsactx = this->rsactx;
    this->listenerContext->clientSocket = this->clientSocket;
    this->listenerContext->networkNodes = &this->networkNodes;
    this->listenerContext->listenerThread = this->listenerThread;
    this->listenerContext->newSessionSetCallback = this->newSessionSetCallback;
    this->listenerContext->sessionClearedCallback = this->sessionClearedCallback;
    this->listenerContext->messageReceivedCallback = this->messageReceivedCallback;

    return pthread_create(listenerThread, 0, this->dataListener, listenerContext) == 0;
}

int Client::writeDataWithEncryption(MessageBuilder &mb, NetworkNode *route)
{
    NetworkNode *p = route;

    if (mb.hasAtLeastOneType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_HANDSHAKE_PHASE_TWO | MESSAGE_ADD_SESSION))
    {
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

        mb.setId(p->getId());
    }

    return this->clientSocket->writeData(mb) < 0 ? -1 : 0;
}

int Client::guardHandhsakePhaseOne(RSA_CRYPTO encrctx, AES_CRYPTO aesctx, BYTES *sessionId, BYTES *test)
{
    int ret = 0;

    BYTES key = 0;

    MessageBuilder mb;
    MessageParser mp;

    if (CRYPTO::AES_read_key(aesctx, SESSION_KEY_SIZE, &key) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (mb.handshakePhaseOneRequest(key, this->pubkeypem, encrctx, aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    // send handshake request
    if (this->clientSocket->writeData(mb) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    // wait response from server
    if (this->clientSocket->readData(mp) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    // get session id and test phrase from server
    mp.handshakePhaseOneResponse(aesctx, sessionId, test);

cleanup:
    delete[] key;
    key = 0;

    return ret;
}

int Client::guardHandshakePhaseTwo(const BYTE *sessionId, const BYTE *test)
{
    if (not sessionId or not test)
    {
        return -1;
    }

    MessageBuilder mb;
    MessageParser mp;

    if (mb.handshakePhaseTwoRequest(sessionId, test, this->rsactx) < 0)
    {
        return -1;
    }

    if (this->clientSocket->writeData(mb) < 0)
    {
        return -1;
    }

    if (this->clientSocket->readData(mp) < 0)
    {
        return -1;
    }

    return mp.handshakePhaseTwoResponse();
}

int Client::performGuardHandshake(NetworkNode *guardNode)
{
    if (not guardNode)
    {
        return -1;
    }

    int ret = 0;

    BYTES sessionId = 0;
    BYTES test = 0;

    if (this->guardHandhsakePhaseOne(guardNode->getRSA(), guardNode->getAES(), &sessionId, &test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (this->guardHandshakePhaseTwo(sessionId, test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    guardNode->setId(sessionId);

cleanup:
    delete[] sessionId;
    delete[] test;

    sessionId = 0;
    test = 0;

    return ret;
}
