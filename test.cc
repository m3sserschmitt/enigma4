#include "message_builder.hh"
#include "message_parser.hh"


#include <iostream>
#include "util.hh"
// #include <cryptography/cryptography.hh>

using namespace std;

int main()
{
    char *str = new char[100];
    strcpy(str, "hello my friend");

    memcpy(str + 6, str, strlen(str));

    cout << str << "\n";

    return 0;
}