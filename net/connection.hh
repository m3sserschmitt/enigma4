#ifndef CONNECTION_HH
#define CONNECTION_HH

#include "sockets/socket.hh"
#include "session.hh"
#include "messages/message_parser.hh"

class Connection
{
    Socket *sock;
    std::string address;
    SessionManager *sessions;

    Connection(const Connection &);
    const Connection &operator=(const Connection &);

public:
    Connection() : sock(0), sessions(new SessionManager) {}

    Connection(Socket *sock) : sock(sock), sessions(new SessionManager) {}

    ~Connection()
    {
        delete sock;
        delete sessions;
    }

    int addSession(MessageParser &mp, RSA_CRYPTO ctx)
    {
        if (this->sessions->setup(ctx, mp) < 0)
        {
            return -1;
        }

        if (not this->address.size())
        {
            if (not mp.keyExists("pubkey"))
            {
                return -1;
            }

            this->address = mp.getParsedAddress();
        }

        return 0;
    }

    void setAddress(const std::string &address)
    {
        this->address = address;
    }

    AES_CRYPTO getEncryptionContext(const std::string &id) { return this->sessions->getEncryptionContext(id); }

    const std::string &getAddress() const { return this->address; }

    ssize_t readData(MessageParser &mp) const { return this->sock->readData(mp); }

    ssize_t writeData(const BYTE *data, SIZE datalen) const { return this->sock->writeData(data, datalen); }

    void cleanupSession(const std::string &id) { this->sessions->cleanup(id); }
};

#endif
