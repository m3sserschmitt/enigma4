#ifndef CMD_HH
#define CMD_HH

#include <string>

char *getCmdOption(char **argv, int argc, const std::string &option);

bool cmdOptionExists(char **argv, int argc, const std::string &option);

#endif
