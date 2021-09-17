#ifndef UTIL_HH
#define UTIL_HH

#include <string>
#include <vector>
#include <cryptography/types.hh>

const std::string to_lowercase(std::string str);

const std::string strip(std::string str, const char ch);

std::vector<std::string> split(std::string str, const std::string &sep, int max_split);

BYTES read_file(const std::string &filename, const CHAR *open_mode);

void remove_str(std::string &from, const std::string &str);

namespace KEY_UTIL
{
    int PEM_to_byteskey(std::string pem, BYTES *byteskey);

    int get_keydigest(const std::string &pem, BYTES *digest);

    int get_key_hexdigest(const std::string &pem, PLAINTEXT *address);

    int get_key_hexdigest(const std::string &pem, std::string &address);
}

#endif
