#include "session.hh"
#include <string>
#include "util.hh"
#include "message_parser.hh"

using namespace std;

int SessionManager::setup(RSA_CRYPTO rsactx, MessageParser &mp)
{
    AES_CRYPTO ctx = CRYPTO::AES_CRYPTO_new();

    CRYPTO::AES_iv_autoset(1, ctx);
    CRYPTO::AES_iv_append(1, ctx);

    CRYPTO::AES_ctx_dup(ctx, this->aesctx);

    mp.handshake(rsactx, ctx);

    this->set(mp["id"], ctx);

    return 0;
}