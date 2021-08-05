#include "message_builder.hh"
#include "message_parser.hh"

#include <iostream>
#include "util.hh"
// #include <cryptography/cryptography.hh>

int main()
{
    MessageBuilder mb;

    RSA_CRYPTO rsactx = CRYPTO::RSA_CRYPTO_new();
    AES_CRYPTO aesctx = CRYPTO::AES_CRYPTO_new();

    int result = CRYPTO::RSA_init_key_file("client_public.pem", 0, 0, PUBLIC_KEY, rsactx);
    result = CRYPTO::RSA_init_key_file("client_private.pem", 0, 0, PRIVATE_KEY, rsactx);

    result = CRYPTO::RSA_init_ctx(rsactx, ENCRYPT);
    result = CRYPTO::RSA_init_ctx(rsactx, DECRYPT);

    result = CRYPTO::AES_init((BYTES) "pass", 4, 0, 10000, aesctx);

    mb.update((const BYTE *)"pass: hello", 11);
    mb.encrypt(rsactx);

    mb.set_dest_address(rsactx);
    mb.encrypt(aesctx);

    SIZE datalen;
    const BYTE *data = mb.get_data(datalen);

    MessageParser mp;

    mp.update(data, datalen);
    mp.decrypt(aesctx);
    mp.decrypt(rsactx);

    return 0;
}