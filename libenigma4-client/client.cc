#include <string.h>
#include <thread>

#include "enigma4-client/client.hh"

using namespace std;

Client::~Client()
{
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

    this->guardNode = 0;
    this->clientSocket = 0;

    CRYPTO::RSA_CRYPTO_free(this->rsactx);
    CRYPTO::AES_CRYPTO_free(this->aesctx);
}

int Client::initCrypto()
{
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

    newNode->setId(sessionId, SESSION_ID_SIZE);
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
        return SESSION_SET; // handshake successful, no further actions required;
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

    if (this->clientSocket->createConnection(host, port) < 0)
    {
        return -1;
    }

    if (not this->clientSocket->isConnected())
    {
        return -1;
    }

    return 0;
}

NetworkNode *Client::setupNetworkNode(const string &pubkeypem, const BYTE *key, const BYTE *id, SIZE keylen, SIZE idlen)
{
    if (not pubkeypem.size())
    {
        return nullptr;
    }

    NetworkNode *newNetworkNode = new (nothrow) NetworkNode;

    if (not newNetworkNode)
    {
        return nullptr;
    }

    if (newNetworkNode->aesctxDuplicate(this->aesctx) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    if (newNetworkNode->pubkeyInit(pubkeypem) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    if (newNetworkNode->aesctxInit(key, keylen) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    if (newNetworkNode->setId(id, idlen) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    const CHAR *hexdigest = newNetworkNode->getPubkeyHexDigest();
    this->networkNodes[hexdigest] = newNetworkNode;

    return newNetworkNode;
}

NetworkNode *Client::setupNetworkNode2(const std::string &pubkeyfile, const BYTE *sessionKey, const BYTE *sessionId, SIZE keylen, SIZE idlen)
{
    PLAINTEXT pubkeypem = (PLAINTEXT)readFile(pubkeyfile, "rb");

    return this->setupNetworkNode(pubkeypem, sessionKey, sessionId, keylen, idlen);
}

NetworkNode *Client::setupNetworkNode3(const string &address, const BYTE *sessionKey, const BYTE *sessionId, SIZE keylen, SIZE idlen)
{
    if (not address.size())
    {
        return nullptr;
    }

    NetworkNode *newNetworkNode = new (nothrow) NetworkNode;

    if (not newNetworkNode)
    {
        return nullptr;
    }

    if (newNetworkNode->aesctxDuplicate(this->aesctx) < 0)
    {
        return nullptr;
    }

    if (newNetworkNode->aesctxInit(sessionKey, keylen) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    if (newNetworkNode->setId(sessionId, idlen) < 0)
    {
        delete newNetworkNode;
        return nullptr;
    }

    newNetworkNode->setPubkeyHexDigest(address);

    this->networkNodes[address] = newNetworkNode;
    this->networkNodes[newNetworkNode->encodeId()] = newNetworkNode;

    BYTES addressBytes = nullptr;
    if (CRYPTO::fromHex(address.c_str(), &addressBytes) < 0)
    {
        delete[] addressBytes;
        delete newNetworkNode;
        return nullptr;
    }

    newNetworkNode->setPubkeyDigest(addressBytes);

    delete[] addressBytes;

    return newNetworkNode;
}

const string Client::addNodeToCircuit(const std::string &pubkeypem, const std::string &lastAddress, bool newSessionId)
{
    NetworkNode *lastNode = this->networkNodes[lastAddress];

    if (not lastNode)
    {
        return "";
    }

    NetworkNode *newNode;

    if (newSessionId)
    {
        newNode = this->setupNetworkNode(pubkeypem);
    }
    else
    {
        newNode = this->setupNetworkNode(pubkeypem, nullptr, lastNode->getId());
    }

    if (not newNode)
    {
        return "";
    }

    newNode->setPrevious(lastNode);
    lastNode->setNext(newNode);

    this->addNewSession(newNode);

    return newNode->getPubkeyHexDigest();
}

int Client::addNodeToCircuit(const string &address, const string &lastAddress, const BYTE *sessionId, const BYTE *sessionKey)
{
    NetworkNode *lastNode = this->networkNodes[lastAddress];

    if (not lastNode)
    {
        return -1;
    }

    NetworkNode *newNode = this->networkNodes[address];

    if (not newNode and not(newNode = this->setupNetworkNode3(address, sessionKey, sessionId)))
    {
        return -1;
    }
    else if (newNode)
    {
        newNode->setPrevious(lastNode);
        lastNode->setNext(newNode);
    }

    return 0;
}

int Client::addNodeToCircuit(NetworkNode *node, const std::string &lastAddress)
{
    NetworkNode *lastNode = this->networkNodes[lastAddress];

    if (not lastNode)
    {
        return -1;
    }

    node->setPrevious(lastNode);
    lastNode->setNext(node);

    return 0;
}

int Client::readData(BYTES *data, std::string &sessionId)
{
    MessageParser mp;

    if (this->clientSocket->readData(mp) < 0)
    {
        return -1;
    }

    MessageProcessingStatus status = processIncomingMessage(mp, this->rsactx, this->aesctx, &this->networkNodes);

    if (status == PROCESSING_ERROR || status == DECRYPTION_FAILED)
    {
        return -1;
    }

    const BYTE *payload = mp.getPayload();
    SIZE payloadSize = mp.getPayloadSize();

    if (not *data and not(*data = new BYTE[payloadSize + 1]))
    {
        return -1;
    }

    memcpy(*data, payload, payloadSize);
    (*data)[payloadSize] = 0;
    sessionId = mp.getParsedId();

    return payloadSize;
}

const string Client::addNodeToCircuit2(const std::string &pubkeyfile, const std::string &lastAddress, bool newSessionId)
{
    PLAINTEXT pubkeypem = (PLAINTEXT)readFile(pubkeyfile, "rb");

    return addNodeToCircuit(pubkeypem, lastAddress, newSessionId);
}

int Client::readData()
{
    MessageParser mp;

    if (this->clientSocket->readData(mp) < 0)
    {
        return -1;
    }

    MessageProcessingStatus status = processIncomingMessage(mp, this->rsactx, this->aesctx, &this->networkNodes);

    const CHAR *sessionId = mp.getParsedId().c_str();

    if (status == MESSAGE_DECRYPTED_SUCCESSFULLY and this->messageReceivedCallback)
    {
        this->messageReceivedCallback(mp.getPayload(), mp.getPayloadSize(), sessionId, "Guard Node", mp.getParsedNextAddress().c_str());
    }
    else if (status == SESSION_SET and this->newSessionSetCallback)
    {
        const BYTE *sessionKey = this->networkNodes[sessionId]->getSessionKey();
        this->newSessionSetCallback(sessionId, sessionKey, SESSION_KEY_SIZE, "Guard Node");
    }
    else if (status == SESSION_CLEARED and this->sessionClearedCallback)
    {
        this->sessionClearedCallback(mp.getParsedId().c_str(), "Guard Node");
    }

    return 0;
}

int Client::addSession(const string &address, const BYTE *sessionId, const BYTE *sessionKey)
{
    return this->setupNetworkNode3(address, sessionKey, sessionId) ? 0 : -1;
}

int Client::createConnection(const string &host, const string &port, const string &pubkeypem)
{
    if (this->connectSocket(host, port) < 0)
    {
        return -1;
    }

    if (not this->clientSocket->isConnected())
    {
        return -1;
    }

    this->guardNode = this->setupNetworkNode(pubkeypem);
    
    if(not this->guardNode)
    {
        return -1;
    }

    string guardAddress = this->guardNode->getPubkeyHexDigest();

    if (guardAddress.empty())
    {
        delete this->guardNode;
        this->guardNode = 0;
        return -1;
    }

    if (this->performGuardHandshake(this->guardNode) < 0)
    {
        delete this->guardNode;
        this->guardNode = 0;
        return -1;
    }

    return 0;
}

int Client::createConnection2(const string &host, const string &port, const string &pubkeyfile)
{
    PLAINTEXT pubkeypem = (PLAINTEXT)readFile(pubkeyfile, "rb");

    return createConnection(host, port, pubkeypem);
}

int Client::writeDataWithEncryption(MessageBuilder &mb, NetworkNode *node)
{
    NetworkNode *p = node;

    if (mb.hasAtLeastOneType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_HANDSHAKE_PHASE_TWO | MESSAGE_ADD_SESSION))
    {
        p = p->getPrevious();
    }

    NetworkNode *next;

    for (; p; p = p->getPrevious())
    {
        next = p->getNext();
        mb.setNext((next ? next : p)->getPubkeyDigest());

        if (mb.encrypt(p) < 0)
        {
            return -1;
        }

        mb.setId(p->getId());
    }

    return this->clientSocket->writeData(mb) < 0 ? -1 : 0;
}

int Client::guardHandshakePhaseOne(RSA_CRYPTO encrctx, AES_CRYPTO aesctx, BYTES *sessionId, BYTES *test)
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

    if (this->guardHandshakePhaseOne(guardNode->getRSA(), guardNode->getAES(), &sessionId, &test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (this->guardHandshakePhaseTwo(sessionId, test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    guardNode->setId(sessionId, SESSION_ID_SIZE);

cleanup:
    delete[] sessionId;
    delete[] test;

    sessionId = 0;
    test = 0;

    return ret;
}

Connection *Client::getGuardConnection()
{
    Connection *conn = new Connection();

    if (not conn)
    {
        return 0;
    }

    const BYTE *sessionId = this->getGuardSessionId();
    const BYTE *sessionKey = this->getGuardSessionKey();

    conn->setSocket(this->clientSocket);
    conn->addSession(sessionId, sessionKey);
    conn->setAddress(this->guardNode->getPubkeyHexDigest());

    this->clientSocket = 0;

    delete[] sessionId;
    delete[] sessionKey;

    sessionId = 0;
    sessionKey = 0;

    return conn;
}
