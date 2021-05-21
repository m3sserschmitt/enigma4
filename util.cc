#include "util.hh"

using namespace std;

string to_lowercase(string str)
{
    for (unsigned int i = 0; i < str.size(); i++)
        if (str[i] >= 65 && str[i] <= 90)
            str[i] += 32;

    return str;
}

string strip(string str, char ch)
{
    if (!str.size())
        return str;

    size_t __begin = str.find_first_not_of(ch);
    size_t __end = str.find_last_not_of(ch);
    
    str = str.substr(__begin, __end - __begin + 1);

    return str;
}
