#include "./onion_routing_app.hh"

#include "../protocol/message_parser.hh"

#include "../onion_routing/client.hh"

#include "../util/debug.hh"

using namespace std;

RSA_CRYPTO OnionRoutingApp::rsactx;

string OnionRoutingApp::pubkeyfile;
string OnionRoutingApp::privkeyfile;

string OnionRoutingApp::address;
string OnionRoutingApp::pubkey;

std::list<Client *> OnionRoutingApp::peers;
std::map<string, Connection *> OnionRoutingApp::clients;

OnionRoutingApp::OnionRoutingApp(const string &pubkey_file, const string &privkey_file)
{
    this->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)read_file(pubkey_file, "rb");

    this->pubkey = key;
    this->pubkeyfile = pubkey_file;
    this->privkeyfile = privkey_file;

    SUCCESS("App: private key initialization: " << CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx));
    SUCCESS("App: RSA decryption initialization: " << CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT));

    KEY_UTIL::get_key_hexdigest(key, this->address);
}

int OnionRoutingApp::connect_peer(const string &host, const string &port, const string &pubkeyfile)
{
    Client *client = new Client(OnionRoutingApp::pubkeyfile, OnionRoutingApp::privkeyfile);

    if (client->create_connection(host, port, pubkeyfile) < 0)
    {
        FAILURE("Connection to " << host << ":" << port << " failed.");
        return -1;
    }

    SUCCESS("Connection to " << host << ":" << port << " (address: " << client->get_server_address() << ") succeeded.");

    peers.push_back(client);
    clients[client->get_server_address()] = new Connection(client->get_socket());

    return 0;
}

int OnionRoutingApp::join_network(const string &netfile)
{
    string netfile_content = (const CHAR *)read_file(netfile, "r");

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

        if (tokens.size() != 3)
        {
            valid_entries--;
            continue;
        }

        if (connect_peer(tokens[0], tokens[1], tokens[2]) == 0)
        {
            connections++;
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

OnionRoutingApp &OnionRoutingApp::create_app(const string &pubkey_file, const string &privkey_file)
{
    static OnionRoutingApp app(pubkey_file, privkey_file);

    return app;
}

int OnionRoutingApp::try_handshake(MessageParser &mp, Connection *conn)
{
    if (not mp.is_handshake())
    {
        return -1;
    }

    NEWLINE();
    INFO("Handshake received.");

    if (conn->add_session(mp, OnionRoutingApp::rsactx) < 0)
    {
        INFO("Handshake failed.");
        return -1;
    }

    INFO("Handshake completed: " << conn->get_address() << "; session ID: " << mp.get_parsed_id());

    OnionRoutingApp::clients.insert(pair<string, Connection *>(mp.get_parsed_address(), conn));

    return 0;
}

int OnionRoutingApp::forward_message(MessageParser &mp)
{
    mp.remove_next();
    string next_address = mp.get_parsed_next_address();

    map<string, Connection *>::iterator next = clients.find(next_address);

    INFO("Next address: " << next_address << "; session ID: " << mp.get_parsed_id());

    if (next == clients.end())
    {
        FAILURE("Address not found: " << next_address);
        return -1;
    }

    INFO("Forwarding to " << next->first);

    return next->second->write_data(mp.get_data(), mp.get_datalen()) > 0 ? 0 : -1;
}

int OnionRoutingApp::action(MessageParser &mp, Connection *conn)
{
    if (try_handshake(mp, conn) == 0)
    {
        return 0;
    }

    if (mp.decrypt(conn->sessions) < 0)
    {
        return -1;
    }

    INFO("Message decrypted successfully.");

    if (mp.is_exit())
    {
        INFO("EXIT received for session ID: " << mp.get_parsed_id());
        conn->sessions->cleanup(mp.get_parsed_id());
    }

    if (forward_message(mp) < 0)
    {
        return -1;
    }

    return 0;
}

int OnionRoutingApp::redirect(Connection *const conn)
{
    MessageParser mp;

    while (conn->read_data(mp) > 0)
    {
        NEWLINE();
        INFO("Data received: " << mp.get_datalen() << " bytes");

        action(mp, conn);

        mp.clear();
    }

    return 0;
}

void *OnionRoutingApp::new_thread(void *args)
{
    Connection *conn = ((Connection *)args);

    if (not conn)
    {
        return 0;
    }

    redirect(conn);

    clients.erase(conn->get_address());
    delete conn;

    return 0;
}

int OnionRoutingApp::handle_client(int clientsock)
{
    pthread_t thread;
    Connection *connection = new Connection(new Socket(clientsock));

    return pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
