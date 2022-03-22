#ifndef STRING_UTIL_HH
#define STRING_UTIL_HH

#include <string>
#include <vector>

const std::string toLowercase(std::string str);

const std::string strip(std::string str, const char ch);

std::vector<std::string> split(std::string str, const std::string &sep, int max_split);

void removeFromString(std::string &from, const std::string &str);

#endif
