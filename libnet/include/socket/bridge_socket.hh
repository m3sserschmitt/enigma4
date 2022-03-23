#ifndef BRIDGE_SOCKET_HH
#define BRIDGE_SOCKET_HH

#include "socket.hh"

class BridgeSocket : public Socket
{

    BridgeSocket(const BridgeSocket &);
    const BridgeSocket &operator=(const BridgeSocket &);

public:
    BridgeSocket() : Socket() {}

    int createConnection(const std::string &host, const std::string &port, bool nonBlocking = false) { return -1; }

    ssize_t readData(MessageParser &mp)
    {
        int fd = this->getFd();
        BYTES localBuffer = const_cast<BYTES>(this->getBuffer());

        memset(localBuffer, 255, SESSION_ID_SIZE + MESSAGE_ADDRESS_SIZE);

        ssize_t bytesRead = read(fd, localBuffer + SESSION_ID_SIZE + MESSAGE_ADDRESS_SIZE, this->getMaxSocketBuffRead());

        if (bytesRead < 0)
        {
            return -1;
        }

        mp.setPayload(localBuffer, bytesRead + SESSION_ID_SIZE + MESSAGE_ADDRESS_SIZE);
        mp.setMessageType(MESSAGE_BRADCAST);

        return bytesRead;
    }

    ssize_t writeData(const MessageBuilder &mb) const
    {
        return write(this->getFd(), mb.getPayload(), mb.getPayloadSize());
    }
};

#endif