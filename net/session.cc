#include "session.hh"

#include "messages/message_parser.hh"

using namespace std;

int SessionManager::set(const BYTE *sessionId, const BYTE *sessionKey)
{
    int ret = 0;

    BASE64 encodedSessionId = 0;
    AES_CRYPTO newaesctx = CRYPTO::AES_CRYPTO_new();

    if (not newaesctx)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::base64_encode(sessionId, SESSION_ID_SIZE, &encodedSessionId) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_setup_key(sessionKey, SESSION_KEY_SIZE, newaesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    if (CRYPTO::AES_ctx_dup(newaesctx, this->aesctx) < 0)
    {
        ret = -1;
        goto cleanup;
    }

    this->keys[encodedSessionId] = newaesctx;

cleanup:
    //CRYPTO::AES_CRYPTO_free(newaesctx);

    delete encodedSessionId;
    encodedSessionId = 0;

    return ret;
}
