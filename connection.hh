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

    Connection(const Connection &);
    const Connection &operator=(const Connection &);

public:
    Session *session;

    Connection() : sock(0), session(new Session) {}
    Connection(Socket *sock) : sock(sock), session(new Session) {}

    ssize_t read_data(MessageParser &mp) const { return this->sock->read_data(mp); }
    ssize_t write_data(const BYTE *data, SIZE datalen) const { return this->sock->write_data(data, datalen); }
};

#endif
