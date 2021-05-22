#ifndef UTIL_HH
#define UTIL_HH

#include <string>
#include <vector>

std::string to_lowercase(std::string str);

std::string strip(std::string str, char ch);

std::vector<std::string> split(std::string str, std::string sep, int max_split);

#endif
