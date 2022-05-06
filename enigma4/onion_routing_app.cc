#include "onion_routing_app.hh"

#include "message/message_parser.hh"
#include "enigma4-client/tls_client.hh"
#include "util/debug.hh"

#include <thread>

using namespace std;

RSA_CRYPTO OnionRoutingApp::rsactx = 0;

string OnionRoutingApp::pubkeyfile;
string OnionRoutingApp::privkeyfile;

string OnionRoutingApp::address;
string OnionRoutingApp::pubkey;

std::map<std::string, Connection *> OnionRoutingApp::connections;

OnionRoutingApp::OnionRoutingApp(const string &pubkey_file, const string &privkey_file)
{
    this->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)readFile(pubkey_file, "rb");

    this->pubkey = key;
    this->pubkeyfile = pubkey_file;
    this->privkeyfile = privkey_file;

    SUCCESS("App: private key initialization: ", CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx));
    SUCCESS("App: RSA decryption initialization: ", CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT));

    KEY_UTIL::getKeyHexDigest(key, this->address);
}

int OnionRoutingApp::joinNetwork(const string &netfile)
{
    string netfile_content = (const CHAR *)readFile(netfile, "r");

    vector<string> lines = split(netfile_content, "\n", -1);

    int valid_entries = lines.size();

    vector<string>::iterator it = lines.begin();
    vector<string>::iterator it_end = lines.end();

    vector<string> tokens;

    int connections = 0;

    NEWLINE();

    for (; it != it_end; it++)
    {
        tokens = split(*it, " ", -1);

        // all entries from netfile should contain a hostname, a port number and a public key file
        if (tokens.size() != 3)
        {
            valid_entries--;
            continue;
        }

        Client *newClient = new TlsClient();

        newClient->setClientPublicKeyPEM(OnionRoutingApp::pubkey);
        newClient->loadClientPrivateKeyFile(OnionRoutingApp::privkeyfile);

        if (newClient->createConnection2(tokens[0], tokens[1], tokens[2]) < 0)
        {
            continue;
        }

        Connection *conn = newClient->getGuardConnection();

        conn->setConnectionPeerTypeServer();

        delete newClient;
        newClient = 0;

        pthread_t thread;
        if (pthread_create(&thread, 0, newThread, conn) != 0)
        {
            continue;
        }

        connections++;
    }

    int ret;
    if (connections == valid_entries)
    {
        SUCCESS("All connections succeeded.");
        ret = 0;
    }
    else if (not connections)
    {
        FAILURE("All connections failed; network connection failed.");
        ret = -1;
    }
    else
    {
        WARNING("Some connections failed.");
        ret = 1;
    }

    NEWLINE();

    return ret;
}

int OnionRoutingApp::handshakePhaseOne(Connection *conn, BYTES *sessionKey, BYTES *sessionId, BYTES *test, std::string &pubkeypem)
{
    MessageParser mp;

    if (conn->readData(mp) < 0)
    {
        return -1;
    }

    if (not mp.hasType(MESSAGE_HANDSHAKE_PHASE_ONE | MESSAGE_ENC_RSA | MESSAGE_ENC_AES))
    {
        return -1;
    }

    int ret = 0;

    AES_CRYPTO aesctx = CRYPTO::AES_CRYPTO_new();

    MessageBuilder mb;

    if (CRYPTO::AES_init_ctx(ENCRYPT, aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (mp.handshakePhaseOneRequest(OnionRoutingApp::rsactx, aesctx, pubkeypem) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_read_key(aesctx, SESSION_KEY_SIZE, sessionKey) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::rand_bytes(SESSION_ID_SIZE, sessionId) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::rand_bytes(HANDSHAKE_TEST_PHRASE_SIZE, test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (mb.handshakePhaseOneResponse(*sessionId, *test, aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (conn->writeData(mb) < 0)
    {
        ret = -1;
    }

cleanup:
    CRYPTO::AES_CRYPTO_free(aesctx);

    return ret;
}

int OnionRoutingApp::handshakePhaseTwo(Connection *conn, const BYTE *sessionId, const BYTE *test, const std::string &pubkeypem)
{
    MessageParser mp;

    if (conn->readData(mp) < 0)
    {
        return -1;
    }

    if (not mp.hasType(MESSAGE_HANDSHAKE_PHASE_TWO | MESSAGE_ENC_RSA))
    {
        return -1;
    }

    RSA_CRYPTO rsaverifctx = CRYPTO::RSA_CRYPTO_new();

    if (not rsaverifctx)
    {
        return -1;
    }

    int ret = 0;

    MessageBuilder mb;

    if (CRYPTO::RSA_init_key(pubkeypem, 0, 0, PUBLIC_KEY, rsaverifctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::RSA_init_ctx(rsaverifctx, VERIFY) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (mp.handshakePhaseTwoRequest(rsaverifctx, sessionId, test) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (mb.handshakePhaseTwoResponse() < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (conn->writeData(mb) < 0)
    {
        ret = -1;
    }

cleanup:
    CRYPTO::RSA_CRYPTO_free(rsaverifctx);

    return ret;
}

int OnionRoutingApp::doHandshake(Connection *conn)
{
    ConnectionPeerType peerType = conn->getConnectionPeerType();

    if (peerType == SERVER_PEER)
    {
        return 0;
    }
    else if (peerType == NETWORK_GRAPH_PEER)
    {
        conn->setAddress(DIRECTORY_NODE_ADDRESS);

        return 0;
    }

    int ret = 0;

    BYTES sessionKey = 0;
    BYTES sessionId = 0;
    BYTES test = 0;

    string pubkeypem;

    if (handshakePhaseOne(conn, &sessionKey, &sessionId, &test, pubkeypem) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (handshakePhaseTwo(conn, sessionId, test, pubkeypem) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    conn->setAddressFromPubkey(pubkeypem);
    conn->addSession(sessionId, sessionKey);

cleanup:
    delete[] sessionKey;
    delete[] sessionId;
    delete[] test;

    sessionKey = 0;
    sessionId = 0;
    test = 0;

    return ret;
}

int OnionRoutingApp::forwardMessage(MessageParser &mp)
{
    string next_address = mp.getParsedNextAddress();

    map<string, Connection *>::iterator next = connections.find(next_address);

    INFO("Next address: ", next_address, "; session ID: ", mp.getParsedId());

    // try to find next address into local connections
    if (next == connections.end())
    {

        FAILURE("Address not found ", next_address);

        return -1;
    }

    INFO("Forwarding ", mp.getDatalen(), " bytes to ", next_address);

    return next->second->writeData(mp.getData(), mp.getDatalen()) > 0 ? 0 : -1;
}

int OnionRoutingApp::addSession(MessageParser &mp, Connection *conn)
{
    if (not mp.isAddSessionMessage())
    {
        return 1;
    }

    BYTES sessionId = 0;
    BYTES sessionKey = 0;

    int ret = 0;

    if (mp.addSessionMessage(OnionRoutingApp::rsactx, &sessionId, &sessionKey) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (conn->addSession(sessionId, sessionKey) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    INFO("New session id: ", mp.getParsedId(), "; source address: ", conn->getAddress());

cleanup:
    delete[] sessionId;
    delete[] sessionKey;

    sessionId = 0;
    sessionKey = 0;

    return ret;
}

int OnionRoutingApp::broadcast(MessageParser &mp, Connection *conn)
{
    if (not mp.isBroadcast())
    {
        return 1;
    }

    mp.broadcast();

    const string &destinationAddress = mp.getParsedNextAddress();
    map<string, Connection *>::iterator connection;

    if (destinationAddress != conn->getAddress())
    {
        INFO("Broadcast message received; redirecting to ", destinationAddress);

        connection = connections.find(destinationAddress);

        if (connection != connections.end())
        {
            connection->second->writeData(mp.getPayload() + SESSION_ID_SIZE + MESSAGE_ADDRESS_SIZE, mp.getPayloadSize() - SESSION_ID_SIZE - MESSAGE_ADDRESS_SIZE);
        }
        else
        {
            ERROR("Destination address not found: ", destinationAddress);
        }
    }
    else
    {
        INFO("Broadcast message from ", conn->getAddress(), " received; broadcasting message");

        connection = OnionRoutingApp::connections.begin();
        map<string, Connection *>::iterator endIt = connections.end();

        for (; connection != endIt; connection++)
        {
            if (connection->second->getAddress() != destinationAddress)
            {
                connection->second->writeData(mp.getData(), mp.getDatalen());
            }
        }
    }

    return 0;
}

int OnionRoutingApp::processMessage(MessageParser &mp, Connection *conn)
{
    switch (addSession(mp, conn))
    {
    case -1:
        return -1;
    case 0:
        return 0;
    }

    if (broadcast(mp, conn) == 0)
    {
        return 0;
    }

    switch (mp.removeEncryptionLayer(conn))
    {
    case -1:
    case 1:
        return -1;
    }

    removeSession(mp, conn);

    return forwardMessage(mp);
}

int OnionRoutingApp::redirect(Connection *const conn)
{
    MessageParser mp;

    while (conn->readData(mp) > 0)
    {
        NEWLINE();
        INFO("Data received: ", mp.getDatalen(), " bytes.");

        processMessage(mp, conn);

        mp.reset();
    }

    return 0;
}

void *OnionRoutingApp::newThread(void *args)
{
    Connection *conn = ((Connection *)args);

    if (not conn or doHandshake(conn) < 0)
    {
        return 0;
    }

    const string &remoteAddress = conn->getAddress();

    INFO("Successfully connected to: ", remoteAddress);
    OnionRoutingApp::addConnection(conn);

    OnionRoutingApp::redirect(conn);

    OnionRoutingApp::removeConnection(conn);
    INFO("Connection to ", remoteAddress, " closed.");

    delete conn;
    conn = 0;

    return 0;
}

int OnionRoutingApp::handleClient(Socket *sock)
{
    pthread_t thread;
    Connection *connection = new Connection(sock);

    return pthread_create(&thread, 0, this->newThread, (void *)connection) == 0 ? 0 : -1;
}
