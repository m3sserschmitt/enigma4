#include "onion_routing.hh"
#include "message_parser.hh"
#include "util.hh"
#include "debug.hh"

#include <iostream>
#include <unistd.h>
#include <string.h>

using namespace std;

std::map<string, Connection *> OnionRoutingApp::clients;
RSA_CRYPTO OnionRoutingApp::rsactx;
string OnionRoutingApp::address;

OnionRoutingApp::OnionRoutingApp(const string &pubkey_file, const string &privkey_file)
{
    this->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)read_file(pubkey_file, "rb");

    INFO("Privkey init: " << CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx));
    INFO("RSA decr init: " << CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT));

    KEY_UTIL::get_key_hexdigest(key, this->address);
}

OnionRoutingApp &OnionRoutingApp::get_handle(const string &pubkey_file, const string &privkey_file)
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

    INFO("Handshake completed: " << mp["address"] << "; session ID: " << mp["id"]);

    OnionRoutingApp::clients.insert(pair<string, Connection *>(mp["address"], conn));

    return 0;
}

int OnionRoutingApp::forward_message(MessageParser &mp)
{
    mp.remove_next();
    map<string, Connection *>::iterator next = clients.find(mp["next"]);

    INFO("Next address: " << mp["next"] << "; session ID: " << mp["id"]);

    if (next == clients.end())
    {
        FAILED("Address not found: " << mp["next"]);
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
        INFO("EXIT received for session ID: " << mp["id"]);
        conn->sessions->cleanup(mp["id"]);
    }

    forward_message(mp);

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

    delete conn;

    return 0;
}

int OnionRoutingApp::handle_client(int clientsock)
{
    pthread_t thread;
    Connection *connection = new Connection(new Socket(clientsock));

    return pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
