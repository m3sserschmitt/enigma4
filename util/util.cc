#include "util.hh"
#include <stdexcept>

#include "../libcryptography/include/cryptography.hh"

#include <string.h>

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

BYTES readFile(const string &filename, const CHAR *open_mode)
{
    FILE *file = fopen(filename.c_str(), open_mode);

    if(not file)
    {
        throw runtime_error(string("Could not open file ") + filename);
    }

    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTES data = new BYTE[filesize + 1];

    if(not data)
    {
        throw runtime_error("Memory allocation error");
    }

    memset(data, 0, filesize + 1);

    fread(data, sizeof(BYTE), filesize, file);

    fclose(file);

    return data;
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

    from.resize(f_len);
}

int KEY_UTIL::BytesKeyFromPEM(string pem, BYTES *byteskey)
{
    removeFromString(pem, "-----BEGIN PUBLIC KEY-----");
    removeFromString(pem, "-----END PUBLIC KEY-----");
    removeFromString(pem, "\n");

    return CRYPTO::base64_decode(pem.c_str(), byteskey);
}

int KEY_UTIL::getKeyDigest(const string &pem, BYTES *digest)
{
    BYTES byteskey = 0;
    int result = BytesKeyFromPEM(pem, &byteskey);

    if (result < 0)
    {
        delete[] byteskey;
        return -1;
    }

    result = CRYPTO::sha256(byteskey, result, digest);

    delete[] byteskey;
    return result;
}

int KEY_UTIL::getKeyHexDigest(const string &pem, PLAINTEXT *address)
{
    BYTES digest = 0;
    int result = getKeyDigest(pem, &digest);

    if (result < 0)
    {
        delete[] digest;
        digest = 0;
        return -1;
    }

    result = CRYPTO::hex(digest, result, address);

    delete[] digest;
    digest = 0;

    return result;
}

int KEY_UTIL::getKeyHexDigest(const string &pem, string &address)
{
    PLAINTEXT buffer = 0;
    int result = getKeyHexDigest(pem, &buffer);

    if(result < 0)
    {
        return -1;
    }

    address = buffer;

    delete[] buffer;
    return result;
}
