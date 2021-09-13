#include <algorithm>
#include "cmd.hh"

using namespace std;

char *get_cmd_option(char **argv, int argc, const string &option)
{
    char **itr = find(argv, argv + argc, option);
    if (itr != argv + argc && ++itr != argv + argc)
    {
        return *itr;
    }

    return 0;
}

bool cmd_option_exists(char **argv, int argc, const string &option)
{
    return find(argv, argv + argc, option) != argv + argc;
}