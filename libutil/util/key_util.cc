#include "util/key_util.hh"
#include "util/string_util.hh"

using namespace std;

int KEY_UTIL::BytesKeyFromPEM(string pem, BYTES *byteskey)
{
    removeFromString(pem, "-----BEGIN PUBLIC KEY-----");
    removeFromString(pem, "-----END PUBLIC KEY-----");
    removeFromString(pem, "\n");

    return CRYPTO::base64_decode(pem.c_str(), byteskey);
}

int KEY_UTIL::getKeyDigest(const string &pem, BYTES *digest)
{
    BYTES byteskey = 0;
    int result = BytesKeyFromPEM(pem, &byteskey);

    if (result < 0)
    {
        delete[] byteskey;
        return -1;
    }

    result = CRYPTO::sha256(byteskey, result, digest);

    delete[] byteskey;
    return result;
}

int KEY_UTIL::getKeyHexDigest(const string &pem, PLAINTEXT *address)
{
    BYTES digest = 0;
    int result = getKeyDigest(pem, &digest);

    if (result < 0)
    {
        delete[] digest;
        digest = 0;
        return -1;
    }

    result = CRYPTO::hex(digest, result, address);

    delete[] digest;
    digest = 0;

    return result;
}

int KEY_UTIL::getKeyHexDigest(const string &pem, string &address)
{
    PLAINTEXT buffer = 0;
    int result = getKeyHexDigest(pem, &buffer);

    if(result < 0)
    {
        return -1;
    }

    address = buffer;

    delete[] buffer;
    return result;
}