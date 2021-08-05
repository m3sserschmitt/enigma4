#include "util.hh"

#include <cryptography/base64.hh>
#include <cryptography/rsa.hh>
#include <cryptography/sha.hh>

#include <string.h>

using namespace std;

string to_lowercase(const string &str)
{
    string _str = str;
    for (unsigned int i = 0; i < _str.size(); i++)
        if (_str[i] >= 65 && str[i] <= 90)
            _str[i] += 32;

    return _str;
}

string strip(const string &str, char ch)
{
    string _str = str;

    if (!_str.size())
        return str;

    size_t __begin = _str.find_first_not_of(ch);
    size_t __end = _str.find_last_not_of(ch);

    _str = _str.substr(__begin, __end - __begin + 1);

    return _str;
}

vector<string> split(string str, string sep, int max_split)
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

    if (str.size())
    {
        tokens.push_back(str);
    }

    return tokens;
}

BYTES read_file(const string &filename, const CHAR *open_mode)
{
    FILE *file = fopen(filename.c_str(), open_mode);

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTES data = new BYTE[filesize + 1];

    fread(data, sizeof(BYTE), filesize, file);

    fclose(file);

    return data;
}

int get_address(RSA_CRYPTO ctx, string &address)
{
    BYTES key = 0;
    int keylen = CRYPTO::PEM_key_to_DER(ctx, &key);

    if (keylen < 0)
    {
        return -1;
    }

    // compute hash for client public key;
    PLAINTEXT addr = 0;
    if (CRYPTO::sha256(key, keylen, &addr) < 0)
    {
        return -1;
    }

    address = addr;
    delete addr;

    return 0;
}

int get_address(RSA_CRYPTO ctx, BYTES *out)
{
    return CRYPTO::PEM_key_to_DER(ctx, out);
}
