#ifndef UTIL_HH
#define UTIL_HH

#include <string>
#include <vector>
#include <cryptography/types.hh>

std::string to_lowercase(const std::string &str);

std::string strip(const std::string &str, char ch);

std::vector<std::string> split(std::string str, std::string sep, int max_split);

BYTES read_file(const std::string &filename, const CHAR *open_mode);

int get_address(RSA_CRYPTO ctx, std::string &address);

int get_address(const RSA_CRYPTO ctx, BYTES *out);

#endif
