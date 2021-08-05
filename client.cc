#include "client.hh"

#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "util.hh"
#include "types.hh"
#include "message_builder.hh"

#include <cryptography/random.hh>
#include <cryptography/base64.hh>
#include <iostream>

using namespace std;

pthread_mutex_t Client::mt;
queue<string> Client::messages;

Client::Client(string pubkey)
{
    this->pubkey = (PLAINTEXT)read_file(pubkey, "rb");
    this->sock = -1;

    pthread_mutex_init(&this->mt, 0);
}

void *Client::data_listener(void *args)
{
    connection_t *conn = (connection_t *)args;

    // const SIZE maxread = 4096;
    BYTES rawdata = new BYTE[Client::max_message_size];
    ssize_t recvlen;

    cout << "[+] Reading data...\n";

    while ((recvlen = read(conn->clientsock, rawdata, Client::max_message_size)) > 0)
    {
        pthread_mutex_lock(&Client::mt);

        CRYPTO::AES_setup_iv(rawdata, 16, conn->aesctx);

        rawdata += 16;

        rawdata -= 16;

        pthread_mutex_unlock(&Client::mt);
    }

    return 0;
}

int Client::create_connection(string host, string port)
{
    struct sockaddr_in sock_addr;

    this->sock = socket(AF_INET, SOCK_STREAM, 0);

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(atoi(port.c_str()));
    sock_addr.sin_addr.s_addr = inet_addr(host.c_str());

    if (connect(sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0)
    {
        return -1;
    }

    // connection_t *conn = new connection_t;

    // conn->aesctx = this->dest_aesctx;
    // conn->rsactx = this->dest_rsactx;

    // pthread_t new_thread;
    // pthread_create(&new_thread, 0, this->data_listener, (void *)conn);

    return 0;
}

int Client::init_aes(AES_CRYPTO ctx)
{
    BYTES key = 0;
    BYTES salt = 0;

    int ret = 0;

    if (CRYPTO::rand_bytes(32, &key) < 0)
    {
        ret = -1;
        goto __end;
    }

    if (CRYPTO::rand_bytes(8, &salt) < 0)
    {
        ret = -1;
        goto __end;
    }

    if (CRYPTO::AES_init(key, 32, salt, 10000, ctx) < 0)
    {
        ret = -1;
    }

__end:
    delete[] key;
    delete[] salt;

    return ret;
}

int Client::setup_server(std::string keyfile)
{
    this->serv_aesctx = CRYPTO::AES_CRYPTO_new();
    this->serv_rsactx = CRYPTO::RSA_CRYPTO_new();

    if (CRYPTO::RSA_init_key_file(keyfile, 0, 0, PUBLIC_KEY, this->serv_rsactx) < 0)
    {
        return -1;
    }

    if (CRYPTO::RSA_init_ctx(this->serv_rsactx, ENCRYPT) < 0)
    {
        return -1;
    }

    if (this->init_aes(this->serv_aesctx) < 0)
    {
        return -1;
    }

    return 0;
}

int Client::setup_dest(string keyfile)
{
    this->dest_aesctx = CRYPTO::AES_CRYPTO_new();
    this->dest_rsactx = CRYPTO::RSA_CRYPTO_new();

    if (CRYPTO::AES_ctx_dup(this->dest_aesctx, this->serv_aesctx) < 0)
    {
        return -1;
    }

    if (CRYPTO::RSA_init_key_file(keyfile, 0, 0, PUBLIC_KEY, this->dest_rsactx) < 0)
    {
        return -1;
    }

    if (CRYPTO::RSA_init_ctx(this->dest_rsactx, ENCRYPT) < 0)
    {
        return -1;
    }

    if (this->init_aes(this->dest_aesctx) < 0)
    {
        return -1;
    }

    return 0;
}

int Client::get_base64_dest_key(BASE64 *key)
{
    BYTES rawkey = 0;
    int ret = 0;

    if (CRYPTO::AES_read_key(this->serv_aesctx, 32, &rawkey) < 0)
    {
        ret = -1;
        goto __end;
    }

    if (CRYPTO::base64_encode(rawkey, 32, key) < 0)
    {
        ret = -1;
        goto __end;
    }

__end:

    delete[] rawkey;
    return ret;
}

int Client::write_serv(MessageBuilder &mb, bool rsa)
{
    if (rsa and mb.encrypt(this->serv_rsactx) < 0)
    {
        return -1;
    }
    else if (not rsa)
    {
        mb.set_dest_address(this->dest_rsactx);

        if (mb.encrypt(this->serv_aesctx) < 0)
        {
            return -1;
        }
    }

    SIZE outlen;
    const BYTE *data = mb.get_data(outlen);

    return write(this->sock, data, outlen);
}

int Client::write_dest(MessageBuilder &mb, bool rsa)
{
    if (rsa and mb.encrypt(this->dest_rsactx) < 0)
    {
        return -1;
    }
    else if (mb.encrypt(this->dest_aesctx) < 0)
    {
        return -1;
    }

    return this->write_serv(mb);
}

int Client::handshake()
{
    BASE64 enckey = new CHAR[64 + 1];
    if (this->get_base64_dest_key(&enckey) < 0)
    {
        delete enckey;
        return -1;
    }

    MessageBuilder mb("pass: " + string(enckey));
    delete enckey;

    if (this->write_serv(mb, 1) < 0)
    {
        return -1;
    }

    mb.update("pubkey: " + this->pubkey);

    return this->write_serv(mb);
}

int Client::setup_dest_key()
{
    // BASE64 key = 0;
    // this->get_base64_dest_key(&key);

    // string message = "pass: " + string(key);

    // return this->write_dest((BYTES)message.c_str(), message.size(), 1);
    return 0;
}

int Client::write_data(BYTES data, SIZE datalen)
{
    MessageBuilder mb(data, datalen);

    return this->write_dest(mb);
}
