#include "./onion_routing_app.hh"

#include "../protocol/message_parser.hh"

#include "../onion_routing/client.hh"

#include "../util/debug.hh"

#include <thread>

using namespace std;

RSA_CRYPTO OnionRoutingApp::rsactx;

string OnionRoutingApp::pubkeyfile;
string OnionRoutingApp::privkeyfile;

string OnionRoutingApp::address;
string OnionRoutingApp::pubkey;

std::map<string, Connection *> OnionRoutingApp::localConnections;

NetworkBridge *OnionRoutingApp::networkBridge = 0;

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
    if(not networkBridge)
    {
        ERROR("NetworkBridge Object not set for remote connections.")

        return -1;
    }

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

        if(networkBridge->connectRemoteServer(tokens[0], tokens[1], tokens[2], 1) == 0)
        {
            connections ++;
        }
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

OnionRoutingApp &OnionRoutingApp::createApp(const string &pubkey_file, const string &privkey_file)
{
    static OnionRoutingApp app(pubkey_file, privkey_file);

    return app;
}

int OnionRoutingApp::tryHandshake(MessageParser &mp, Connection *conn)
{
    if (not mp.isHandshake())
    {
        return -1;
    }

    if (conn->addSession(mp, OnionRoutingApp::rsactx) < 0)
    {
        FAILURE("Handshake failed for session ID: ", mp.getParsedId());
        return -1;
    }

    SUCCESS("Handshake completed: ", conn->getAddress(), " for session ID: ", mp.getParsedId());

    OnionRoutingApp::localConnections.insert(pair<string, Connection *>(mp.getParsedAddress(), conn));

    return 0;
}

int OnionRoutingApp::forwardMessage(MessageParser &mp)
{
    string next_address = mp.getParsedNextAddress();

    map<string, Connection *>::iterator next = localConnections.find(next_address);

    INFO("Next address: ", next_address, "; session ID: ", mp.getParsedId());

    // try to find next address into local connections
    if (next == localConnections.end())
    {
        // if address not found, try to find it into remote addresses
        if(networkBridge->forwardMessage(mp) < 0)
        {
            FAILURE("Address not found ", next_address);

            return -1;
        }

        INFO("Forwarding to ", next_address);

        return 0;
    }

    INFO("Forwarding ", mp.getDatalen(), " bytes to ", next_address);

    return next->second->writeData(mp.getData(), mp.getDatalen()) > 0 ? 0 : -1;
}

int OnionRoutingApp::action(MessageParser &mp, Connection *conn)
{
    if (tryHandshake(mp, conn) == 0)
    {
        return 0;
    }

    if (mp.removeEncryptionLayer(conn) < 0)
    {
        return -1;
    }

    string session_id = mp.getParsedId();
    // INFO("Message decrypted successfully; Session ID: ", session_id);

    if (mp.isExitSignal())
    {
        INFO("EXIT received for session ID: ", session_id);
        conn->cleanupSession(session_id);
        SUCCESS("Session with ID ", session_id, " erased.");
    }

    return forwardMessage(mp);
}

int OnionRoutingApp::redirect(Connection *const conn)
{
    MessageParser mp;

    while (conn->readData(mp) > 0)
    {
        NEWLINE();
        INFO("Data received: ", mp.getDatalen(), " bytes");

        action(mp, conn);

        mp.reset();
    }

    return 0;
}

void *OnionRoutingApp::newThread(void *args)
{
    Connection *conn = ((Connection *)args);

    if (not conn)
    {
        return 0;
    }

    redirect(conn);

    localConnections.erase(conn->getAddress());
    INFO("Connection to ", conn->getAddress(), " closed.");

    delete conn;

    return 0;
}

int OnionRoutingApp::handleClient(Socket *sock)
{
    pthread_t thread;

    // Socket *sock = new Socket();
    // sock->wrap(clientsock);

    // INFO("Client socket: ", clientsock, "  ", sock->getFd());

    Connection *connection = new Connection(sock);

    return pthread_create(&thread, 0, this->newThread, (void *)connection) ? 0 : -1;
}
