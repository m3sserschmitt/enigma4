#ifndef CONNECTION_HH
#define CONNECTION_HH

#include "sockets/socket.hh"
#include "session.hh"
#include "messages/message_parser.hh"

enum ConnectionPeerType
{
    CLIENT_PEER,
    SERVER_PEER
};

class Connection
{
    Socket *sock;
    std::string address;
    SessionManager sessions;
    ConnectionPeerType connectionPeerType;

    Connection(const Connection &);
    const Connection &operator=(const Connection &);

public:
    Connection() : sock(0), connectionPeerType(CLIENT_PEER) {}

    Connection(Socket *sock) : sock(sock), connectionPeerType(CLIENT_PEER) {}

    ~Connection()
    {
        delete sock;
        sock = 0;
    }

    int addSession(const BYTE *sessionId, const BYTE *sessionKey)
    {
        return this->sessions.set(sessionId, sessionKey);
    }

    int setAddressFromPubkey(const std::string &pubkeypem)
    {
        if (KEY_UTIL::getKeyHexDigest(pubkeypem, this->address) < 0)
        {
            return -1;
        }

        return 0;
    }

    void setAddress(const std::string &address)
    {
        this->address = address;
    }

    void setSocket(Socket *sock)
    {
        this->sock = sock;
    }

    ConnectionPeerType getConnectionPeerType() const { return this->connectionPeerType; }

    void setConnectionPeerTypeServer()
    {
        this->connectionPeerType = SERVER_PEER;
    }

    void setConnectionPeerTypeClient()
    {
        this->connectionPeerType = CLIENT_PEER;
    }

    AES_CRYPTO getEncryptionContext(const std::string &id) { return this->sessions.getEncryptionContext(id); }

    const std::string &getAddress() const { return this->address; }

    ssize_t readData(MessageParser &mp) const { return this->sock->readData(mp); }

    ssize_t writeData(MessageBuilder &mb) const { return this->sock->writeData(mb); }

    ssize_t writeData(const BYTE *data, SIZE datalen) const { return this->sock->writeData(data, datalen); }

    void cleanupSession(const std::string &id) { this->sessions.cleanup(id); }
};

#endif
