#include "message_builder.hh"
#include "message_parser.hh"

#include <iomanip>
#include <iostream>
#include "util.hh"
#include <cryptography/cryptography.hh>
#include <bitset>

using namespace std;

int main()
{
    // int a = 3167;
    // cout << bitset<16>(a) << "\n";

    // unsigned char b = a >> 8;
    // unsigned c = a;

    // cout << bitset<8>(b) << bitset<8>(c) << "\n";

    // int d = b;
    // d <<= 8;
    // d |= c;
    // cout << bitset<16>(d) << "\n";

    // unsigned char data[2];
    // SIZE datalen = 24512;

    // memcpy(data, &datalen, 2);

    // cout << bitset<16>(datalen) << "\n";
    // cout << bitset<8>(data[1]) << bitset<8>(data[0])<< "\n";
    
    MessageBuilder mb;
    AES_CRYPTO aesctx = CRYPTO::AES_CRYPTO_new();
    RSA_CRYPTO rsactx = CRYPTO::RSA_CRYPTO_new();

    CRYPTO::AES_init((BYTES) "passphrase", 10, nullptr, 1000, aesctx);
    CRYPTO::AES_iv_append(1, aesctx);
    CRYPTO::AES_iv_autoset(1, aesctx);

    CRYPTO::RSA_init_key_file("client_public.pem", 0, 0, PUBLIC_KEY, rsactx);
    CRYPTO::RSA_init_key_file("client_private.pem", 0, 0, PRIVATE_KEY, rsactx);
    CRYPTO::RSA_init_ctx(rsactx, ENCRYPT);
    CRYPTO::RSA_init_ctx(rsactx, DECRYPT);

    mb.set_payload("hello");
    mb.encrypt(rsactx);
    mb.set_id((BYTES) "this is id for message");

    mb.set_next((BYTES) "khdasiuohbeojdjadbgnoauhdufjhvnasdhnfadsjhkvf");
    mb.encrypt(aesctx);

    MessageParser mp;
    
    mp.update(mb.get_data(), mb.get_datalen());
    mp.decrypt(aesctx);
    mp.remove_next();
    mp.remove_id();
    mp.decrypt(rsactx);

/*
    AES_CRYPTO aesctx = CRYPTO::AES_CRYPTO_new();
    CRYPTO::AES_iv_append(1, aesctx);
    CRYPTO::AES_iv_autoset(1, aesctx);

    CRYPTO::AES_init((BYTES) "passphrase", 10, nullptr, 1000, aesctx);

    const BYTE *data = (BYTES)"data to be encrypted";
    BYTES encrdata = 0;
    SIZE len = CRYPTO::AES_encrypt(aesctx, data, 20, &encrdata);

    BYTES decrdata = 0;
    len = CRYPTO::AES_decrypt(aesctx, encrdata, len, &decrdata);
    cout << decrdata << "\n";
*/
    return 0;
}