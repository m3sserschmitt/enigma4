#ifndef KEY_UTIL_HH
#define KEY_UTIL_HH

#include "cryptography/cryptography.hh"

#include <string>

namespace KEY_UTIL
{
    int BytesKeyFromPEM(std::string pem, BYTES *byteskey);

    int getKeyDigest(const std::string &pem, BYTES *digest);

    int getKeyHexDigest(const std::string &pem, PLAINTEXT *address);

    int getKeyHexDigest(const std::string &pem, std::string &address);
}

#endif
