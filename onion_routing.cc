#include "onion_routing.hh"
#include "message_parser.hh"
#include "util.hh"

#include <iostream>
#include <unistd.h>
#include <string.h>

using namespace std;

extern int hex(BYTES in, SIZE inlen, PLAINTEXT *out);

std::map<string, Connection *> OnionRoutingApp::clients;
RSA_CRYPTO OnionRoutingApp::rsactx;
string OnionRoutingApp::address;

OnionRoutingApp::OnionRoutingApp(const string &pubkey_file, const string &privkey_file)
{
    this->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)read_file(pubkey_file, "rb");

    cout << "[+] pubkey init: " << CRYPTO::RSA_init_key(key, 0, 0, PUBLIC_KEY, this->rsactx) << "\n";
    cout << "[+] privkey init: " << CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx) << "\n";

    cout << "[+] RSA decr init: " << CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT) << "\n";

    KEY_UTIL::get_key_hexdigest(key, this->address);
}

OnionRoutingApp::~OnionRoutingApp()
{
    CRYPTO::RSA_CRYPTO_free(this->rsactx);
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

    if (conn->session->setup(OnionRoutingApp::rsactx, mp) < 0)
    {
        cout << "\n[+] Handshake failed\n";
        return -1;
    }

    cout << "\n[+] Handshake completed: " << mp["address"] << "\n";
    OnionRoutingApp::clients.insert(pair<string, Connection *>(mp["address"], conn));

    return 0;
}

int OnionRoutingApp::forward_message(MessageParser &mp)
{
    mp.remove_next();
    map<string, Connection *>::iterator next = clients.find(mp["next"]);

    cout << "[+] Next: " << mp["next"] << "\n";

    if (next == clients.end())
    {
        return -1;
    }

    cout << "[+] Forwarding to " << next->first << "\n";

    return next->second->write_data(mp.get_data(), mp.get_datalen()) > 0 ? 0 : -1;
}

int OnionRoutingApp::redirect(Connection *const conn)
{
    MessageParser mp;

    while (conn->read_data(mp) > 0)
    {
        if (try_handshake(mp, conn) == 0)
        {
            mp.clear();

            continue;
        }

        cout << "\n[+] Data received: " << mp.get_datalen() << " bytes\n";
        cout << "[+] Decryption: " << mp.decrypt(conn->session) << "\n";

        forward_message(mp);

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

    // if (handshake(conn) < 0)
    // {
    //     return 0;
    // }

    // const CHAR *clientaddr = insert_client(conn);

    // cout << "[+] New Connection from " << clientaddr << "\n";

    redirect(conn);
    // remove_client(conn, clientaddr);

    // delete[] clientaddr;
    delete conn;

    return 0;
}

int OnionRoutingApp::handle_client(int clientsock)
{
    pthread_t thread;
    Connection *connection = new Connection(new Socket(clientsock));

    // connection->aesctx = CRYPTO::AES_CRYPTO_new();
    // connection->rsactx = CRYPTO::RSA_CRYPTO_new();

    // CRYPTO::AES_iv_append(1, connection->aesctx);
    // CRYPTO::AES_iv_autoset(1, connection->aesctx);

    return pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
