#include "session.hh"

#include "../protocol/message_parser.hh"

using namespace std;

int SessionManager::setup(RSA_CRYPTO rsactx, MessageParser &mp)
{
    AES_CRYPTO ctx = CRYPTO::AES_CRYPTO_new();

    CRYPTO::AES_iv_autoset(1, ctx);
    CRYPTO::AES_iv_append(1, ctx);

    CRYPTO::AES_ctx_dup(ctx, this->aesctx);

    if(mp.handshake(rsactx, ctx) < 0)
    {
        return -1;
    }

    mp.remove_id();

    this->set(mp.get_parsed_id(), ctx);

    return 0;
}
