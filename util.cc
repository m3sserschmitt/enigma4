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

vector<string> split(string str, string sep, int max_split)
{
    vector<string> tokens;
    
    size_t sep_pos;
    int split_index = 0;
    
    if (!str.size())
        return tokens;

    tokens.reserve(10);

    do
    {
        split_index++;
        sep_pos = str.find(sep);
        
        // tokens.resize(tokens.size() + 1);
        tokens.push_back(str.substr(0, sep_pos));
        if (sep_pos == string::npos) {
            // tokens.resize(split_index);
            return tokens;
        }
            
        str = str.substr(sep_pos + sep.size());
        if (split_index == max_split && str.size())
        {
            
            // tokens.resize(tokens.size() + 1);
            tokens.push_back(str);
            // tokens.resize(split_index + 1);
            return tokens;
        }
    } while (true);

    return tokens;
}
