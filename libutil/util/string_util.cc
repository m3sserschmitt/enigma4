#include "util/string_util.hh"

using namespace std;

const string toLowercase(string str)
{
    for (unsigned int i = 0; i < str.size(); i++)
        if (str[i] >= 65 && str[i] <= 90)
            str[i] += 32;

    return str;
}

const string strip(string str, const char ch)
{
    if (!str.size())
        return str;

    size_t __begin = str.find_first_not_of(ch);
    size_t __end = str.find_last_not_of(ch);

    str = str.substr(__begin, __end - __begin + 1);

    return str;
}

vector<string> split(string str, const string &sep, int max_split)
{
    size_t n;
    string token;
    int count = 0;

    vector<string> tokens;

    do
    {
        n = str.find(sep);
        token = str.substr(0, n);

        tokens.push_back(token);

        if (++count == max_split)
        {
            break;
        }

        str = str.substr(n + sep.size());

    } while (n != string::npos);

    if (str.size() and n != string::npos)
    {
        tokens.push_back(str);
    }

    return tokens;
}

void removeFromString(string &from, const string &str)
{
    size_t f_len = from.size();
    size_t s_len = str.size();
    size_t delta = 0;

    size_t j = 0;

    for (size_t i = 0; i < f_len; i++)
    {
        if (from[i] == str[j])
        {
            j++;
        }
        else
        {
            j = 0;
        }

        if (j == s_len)
        {
            delta += s_len;
            // f_len -= s_len;
            j = 0;
        }

        if (delta)
        {
            from[i - delta + 1] = from[i + 1];
        }
    }

    from.resize(f_len - delta);
}
