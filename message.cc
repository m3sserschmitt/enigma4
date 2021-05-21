#include "message.hh"
#include "util.hh"

using namespace std;

Message::Message(){};

Message::Message(string data)
{
    this->update(data);
}

void Message::update(string data)
{
    size_t n = data.find("\r\n");
    size_t p;

    string line;
    string key;
    string value;

    while (n != string::npos)
    {
        line = data.substr(0, n);

        p = data.find(':');

        if (p != string::npos)
        {
            key = strip(to_lowercase(line.substr(0, p)), ' ');
            value = strip(line.substr(p + 1), ' ');

            this->data[key] = value;
        }

        data = data.substr(n + 2);
        n = data.find("\r\n");
    }
}

string Message::operator[](string key)
{
    return this->data[to_lowercase(key)];
}
