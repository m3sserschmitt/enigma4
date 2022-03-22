#include "util/util.hh"

#include <stdexcept>
#include <string.h>

using namespace std;

unsigned char *readFile(const string &filename, const char *open_mode)
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
