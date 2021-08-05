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

    cout << "[+] pubkey init: " << CRYPTO::RSA_init_key_file(pubkey_file, 0, 0, PUBLIC_KEY, this->rsactx) << "\n";
    cout << "[+] privkey init: " << CRYPTO::RSA_init_key_file(privkey_file, 0, 0, PRIVATE_KEY, this->rsactx) << "\n";

    // cout << "[+] encr init: " << RSA_init_ctx(this->rsactx, ENCRYPT) << "\n";
    cout << "[+] RSA decr init: " << CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT) << "\n";

    // this->pubkey = (PLAINTEXT)read_file(pubkey_file, "rb");
    get_address(this->rsactx, this->address);
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

int OnionRoutingApp::setup_session_key(BASE64 key, AES_CRYPTO ctx)
{
    BYTES decodedkey = 0;

    if (CRYPTO::base64_decode(key, &decodedkey) < 0)
    {
        delete decodedkey;
        return -1;
    }

    if (CRYPTO::AES_setup_key(decodedkey, 32, ctx) < 0)
    {
        delete decodedkey;
        return -1;
    }

    if (CRYPTO::AES_init(0, 0, 0, 0, ctx) < 0)
    {
        delete decodedkey;
        return -1;
    }

    return 0;
}

int OnionRoutingApp::handshake(connection_t *const conn)
{
    // const size_t maxread = 4096;
    SIZE currentread = 512;

    BYTES rawdata = new BYTE[OnionRoutingApp::max_message_size];
    ssize_t datalen;

    MessageParser mp;

    int ret = 0;

    // first, a 512 bytes message is expected;
    while ((datalen = read(conn->clientsock, rawdata, currentread)) > 0)
    {
        mp.update(rawdata, datalen);

        // if key not available, try RSA decryption;
        if (not CRYPTO::AES_decrypt_ready(conn->aesctx))
        {
            if (mp.decrypt(OnionRoutingApp::rsactx) < 0)
            {
                ret = -1;
                goto __end;
            }
        }
        else if (mp.decrypt(conn->aesctx) < 0) // otherwise, perform AES decryption of data;
        {
            ret = -1;
            goto __end;
        }

        memset(rawdata, 0, OnionRoutingApp::max_message_size);

        mp.parse();

        if (mp.key_exists("pass"))
        {

            if (OnionRoutingApp::setup_session_key((BASE64)mp["pass"].c_str(), conn->aesctx) < 0)
            {
                ret = -1;
                goto __end;
            }
            currentread = OnionRoutingApp::max_message_size;
            // keysetup = true;
        }
        else if (mp.key_exists("pubkey"))
        {
            if (CRYPTO::RSA_init_key(mp["pubkey"], 0, 0, PUBLIC_KEY, conn->rsactx) < 0)
            {
                ret = -1;
                goto __end;
            }

            // pubkeysetup = true;
        }

        mp.clear();

        if (CRYPTO::AES_decrypt_ready(conn->aesctx) and CRYPTO::RSA_pubkey_ready(conn->rsactx))
        {
            break;
        }
    }

__end:
    delete rawdata;

    return ret;
}

int OnionRoutingApp::redirect(connection_t *const conn)
{
    const SIZE maxread = 4096;

    BYTES rawdata = new BYTE[maxread];
    ssize_t datalen;

    BYTES decr = new BYTE[4096];
    SIZE decrlen;
    PLAINTEXT address = 0;

    // MessageParser message;

    while ((datalen = read(conn->clientsock, rawdata, maxread)) > 0)
    {
        // cout << CRYPTO::hex(decr, 32, &address);

        // if ((decrlen = message.update(rawdata, datalen, conn->aesctx)) < 0)
        // {
        // continue;
        // }
    }

    return 0;
}

void *OnionRoutingApp::new_thread(void *args)
{
    connection_t *connection = ((connection_t *)args);

    const SIZE maxread = 4096;

    BYTES rawdata = new BYTE[maxread];
    ssize_t datalen;

    BYTES decr = new BYTE[maxread];
    SIZE decrlen;

    string clientaddr;
    MessageParser message;

    if (not connection)
    {
        goto __end;
    }

    if (OnionRoutingApp::handshake(connection) < 0)
    {
        goto __end;
    }

    // convert public key PEM format to raw bytes;
    if (get_address(connection->rsactx, clientaddr) < 0)
    {
        goto __end;
    }

    cout << "\n[+] Session established: " << clientaddr << "\n";
    OnionRoutingApp::clients.insert(pair<string, connection_t *>(clientaddr, connection));

    OnionRoutingApp::redirect(connection);

    OnionRoutingApp::clients.erase(clientaddr);
    cout << "[+] " << clientaddr << " disconnected\n";

__end:
    close(connection->clientsock);

    CRYPTO::RSA_CRYPTO_free(connection->rsactx);
    CRYPTO::AES_CRYPTO_free(connection->aesctx);

    delete connection;

    delete rawdata;
    delete decr;

    return 0;
}

int OnionRoutingApp::handle_client(int clientsock)
{
    pthread_t thread;

    connection_t *connection = new connection_t;

    connection->clientsock = clientsock;

    connection->aesctx = CRYPTO::AES_CRYPTO_new();
    connection->rsactx = CRYPTO::RSA_CRYPTO_new();

    // connection->skey = 0;
    // connection->pkey = 0;

    // CRYPTO::AES_init(0, 0, 0, 0, connection->aesctx);

    return pthread_create(&thread, 0, this->new_thread, (void *)connection) ? 0 : -1;
}
