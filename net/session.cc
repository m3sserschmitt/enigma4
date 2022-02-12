#include "session.hh"

#include "messages/message_parser.hh"

using namespace std;

int SessionManager::setup(RSA_CRYPTO rsactx, MessageParser &mp)
{
    AES_CRYPTO ctx = CRYPTO::AES_CRYPTO_new();

    CRYPTO::AES_ctx_dup(ctx, this->aesctx);

    if(mp.handshake(rsactx, ctx) < 0)
    {
        return -1;
    }

    this->set(mp.getParsedId(), ctx);

    return 0;
}
