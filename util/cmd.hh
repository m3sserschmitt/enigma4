#include <string>

char *getCmdOption(char **argv, int argc, const std::string &option);
bool cmdOptionExists(char **argv, int argc, const std::string &option);
