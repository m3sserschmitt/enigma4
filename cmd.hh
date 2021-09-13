#include <string>

char *get_cmd_option(char **argv, int argc, const std::string &option);
bool cmd_option_exists(char **argv, int argc, const std::string &option);
