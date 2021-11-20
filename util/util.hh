#ifndef UTIL_HH
#define UTIL_HH

#include <string>
#include <vector>

#include "../libcryptography/include/types.hh"

const std::string toLowercase(std::string str);

const std::string strip(std::string str, const char ch);

std::vector<std::string> split(std::string str, const std::string &sep, int max_split);

BYTES readFile(const std::string &filename, const CHAR *open_mode);

void removeFromString(std::string &from, const std::string &str);

namespace KEY_UTIL
{
    int BytesKeyFromPEM(std::string pem, BYTES *byteskey);

    int getKeyDigest(const std::string &pem, BYTES *digest);

    int getKeyHexDigest(const std::string &pem, PLAINTEXT *address);

    int getKeyHexDigest(const std::string &pem, std::string &address);
}

#endif
