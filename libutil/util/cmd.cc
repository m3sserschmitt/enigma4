#include "util/cmd.hh"

#include <algorithm>

using namespace std;

char *getCmdOption(char **argv, int argc, const string &option)
{
    char **itr = find(argv, argv + argc, option);
    if (itr != argv + argc && ++itr != argv + argc)
    {
        return *itr;
    }

    return 0;
}

bool cmdOptionExists(char **argv, int argc, const string &option)
{
    return find(argv, argv + argc, option) != argv + argc;
}
