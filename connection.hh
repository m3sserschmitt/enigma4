#ifndef _TYPES_HH
#define _TYPES_HH

#include <cryptography/cryptography.hh>
#include <map>
#include <string.h>

#include "socket.hh"
#include "session.hh"
#include "message_parser.hh"

class Connection
{
    Socket *sock;
    std::string address;

    Connection(const Connection &);
    const Connection &operator=(const Connection &);

public:
    SessionManager *sessions;

    Connection() : sock(0), sessions(new SessionManager) {}
    Connection(Socket *sock) : sock(sock), sessions(new SessionManager) {}
    ~Connection()
    {
        delete sock;
        delete sessions;
    }

    int add_session(MessageParser &mp, RSA_CRYPTO ctx)
    {
        this->sessions->setup(ctx, mp);

        if (mp.key_exists("address"))
        {
            this->address = mp["address"];
        }
    }

    const std::string &get_address() const { return this->address; }

    ssize_t read_data(MessageParser &mp) const { return this->sock->read_data(mp); }
    ssize_t write_data(const BYTE *data, SIZE datalen) const { return this->sock->write_data(data, datalen); }
};

#endif
