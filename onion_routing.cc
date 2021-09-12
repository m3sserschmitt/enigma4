#include "onion_routing.hh"
#include "message_parser.hh"
#include "util.hh"

#include <iostream>
#include <unistd.h>
#include <string.h>

using namespace std;

extern int hex(BYTES in, SIZE inlen, PLAINTEXT *out);

std::map<string, connection_t *> OnionRoutingApp::clients;
RSA_CRYPTO OnionRoutingApp::rsactx;
string OnionRoutingApp::address;

OnionRoutingApp::OnionRoutingApp(const string &pubkey_file, const string &privkey_file)
{
    this->rsactx = CRYPTO::RSA_CRYPTO_new();

    PLAINTEXT key = (PLAINTEXT)read_file(pubkey_file, "rb");

    cout << "[+] pubkey init: " << CRYPTO::RSA_init_key(key, 0, 0, PUBLIC_KEY, this->rsactx) << "\n";
    cout << "[+] privkey init: " << CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx) << "\n";

    // cout << "[+] encr init: " << RSA_init_ctx(this->rsactx, ENCRYPT) << "\n";
    cout << "[+] RSA decr init: " << CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT) << "\n";

    // this->pubkey = (PLAINTEXT)read_file(pubkey_file, "rb");
    get_key_hexdigest(key, this->address);
    cout << "[+] current address: " << this->address << "\n";
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

int OnionRoutingApp::setup_session_key(MessageParser &mp, connection_t *conn)
{

    if (not mp.key_exists("pass"))
    {

        return -1;
    }

    BYTES decodedkey = 0;

    if (CRYPTO::base64_decode(mp["pass"].c_str(), &decodedkey) < 0)
    {
        delete decodedkey;
        return -1;
    }

    if (CRYPTO::AES_setup_key(decodedkey, 32, conn->aesctx) < 0)
    {
        delete decodedkey;
        return -1;
    }

    if (CRYPTO::AES_init(0, 0, 0, 0, conn->aesctx) < 0)
    {
        delete decodedkey;
        return -1;
    }

    return 0;
}

int OnionRoutingApp::setup_session_pkey(MessageParser &mp, connection_t *conn)
{
    if (mp.key_exists("pubkey"))
    {
        if (CRYPTO::RSA_init_key(mp["pubkey"], 0, 0, PUBLIC_KEY, conn->rsactx) < 0)
        {
            return -1;
        }

        conn->keydigest = 0;
        get_keydigest(mp["pubkey"], &conn->keydigest);
    }

    return 0;
}

int OnionRoutingApp::handshake(connection_t *const conn)
{
    MessageParser mp;

    while (conn->sock->read_data(mp) > 0)
    {
        if (mp.decrypt(OnionRoutingApp::rsactx) < 0 and mp.decrypt(conn->aesctx) < 0)
        {
            return -1;
        }

        mp.parse();

        setup_session_key(mp, conn);
        setup_session_pkey(mp, conn);

        mp.clear();

        if (CRYPTO::AES_decrypt_ready(conn->aesctx) and CRYPTO::RSA_pubkey_ready(conn->rsactx))
        {
            break;
        }
    }

    return 0;
}

const CHAR *OnionRoutingApp::insert_client(connection_t *const conn)
{
    PLAINTEXT clientaddr = 0;
    CRYPTO::hex(conn->keydigest, 32, &clientaddr);

    cout << "\n[+] Session established: " << clientaddr << "\n";
    OnionRoutingApp::clients.insert(pair<string, connection_t *>(clientaddr, conn));

    return clientaddr;
}

int OnionRoutingApp::redirect(connection_t *const conn)
{
    MessageParser mp;
    map<string, connection_t *>::iterator next;

    while (conn->sock->read_data(mp) > 0)
    {
        mp.decrypt(conn->aesctx);
        mp.remove_next();

        cout << "[+] Data received\n";
        if ((next = clients.find(mp["next"])) != clients.end())
        {
            cout << "[+] Forwarding to " << next->first << "\n";
            next->second->sock->write_data(mp.get_data(), mp.get_datalen());
        }
    }

    return 0;
}

int OnionRoutingApp::remove_client(connection_t *conn, const CHAR *clientaddr)
{
    OnionRoutingApp::clients.erase(clientaddr);
    cout << "[+] " << clientaddr << " disconnected\n";

    CRYPTO::RSA_CRYPTO_free(conn->rsactx);
    CRYPTO::AES_CRYPTO_free(conn->aesctx);
    delete conn->sock;

    return 0;
}

void *OnionRoutingApp::new_thread(void *args)
{
    connection_t *conn = ((connection_t *)args);

    if (not conn)
    {
        return 0;
    }

    if (handshake(conn) < 0)
    {
        return 0;
    }

    const CHAR *clientaddr = insert_client(conn);
    redirect(conn);
    remove_client(conn, clientaddr);

    delete[] clientaddr;
    delete conn;

    return 0;
}

int OnionRoutingApp::handle_client(int clientsock)
{
    pthread_t thread;
    connection_t *connection = new connection_t;

    connection->sock = new OSocket(clientsock);

    connection->aesctx = CRYPTO::AES_CRYPTO_new();
    connection->rsactx = CRYPTO::RSA_CRYPTO_new();

    CRYPTO::AES_iv_append(1, connection->aesctx);
    CRYPTO::AES_iv_autoset(1, connection->aesctx);

    return pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
