#ifndef NETWORK_BRIDGE
#define NETWORK_BRIDGE

#include "../protocol/message_parser.hh"

#include "../onion_routing/tls_client.hh"

#include <string>
#include <map>

class NetworkBridge
{
    static std::string pubkeyfile;
    static std::string privkeyfile;

    static std::map<std::string, Client *> remoteServers;

    static IncomingMessageCallback incomingMessageCallback;

    NetworkBridge() {}

    NetworkBridge(const std::string &pubkeyfile, const std::string privkeyfile)
    {
        this->pubkeyfile = pubkeyfile;
        this->privkeyfile = privkeyfile;
    }

    const NetworkBridge &operator=(const NetworkBridge &);

public:
    ~NetworkBridge() {}

    /**
     * @brief Create a Network Bridge object
     * 
     * @param pubkeyfile Public key file used by local application in PEM format.
     * @param privkeyfile Private Key file used by local application in PEM format.
     * @return NetworkBridge& reference to newly create NetworkBridge Object.
     */
    static NetworkBridge &createNetworkBridge(const std::string &pubkeyfile, const std::string privkeyfile)
    {
        static NetworkBridge networkBridge(pubkeyfile, privkeyfile);

        return networkBridge;
    }

    /**
     * @brief Create connection to a remote server
     * 
     * @param host Hostname to connect to.
     * @param port Service port on remote server.
     * @param pubkeyfile Public key of remote server
     * @return int 0 is success, -1 if failure
     */
    int connectRemoteServer(const std::string &host, const std::string &port, const std::string &pubkeyfile, bool tls = false)
    {
        Client *bridgeClient;
        if (not tls)
        {
            bridgeClient = new Client(this->pubkeyfile, this->privkeyfile);
        }
        else
        {
            bridgeClient = new TlsClient(this->pubkeyfile, this->privkeyfile);
        }

        bridgeClient->onIncomingMessage(incomingMessageCallback);

        if (bridgeClient->createConnection(host, port, pubkeyfile) < 0)
        {
            FAILURE("Connection to", host, port, "failed");

            return -1;
        }

        remoteServers.insert(std::pair<std::string, Client *>(bridgeClient->getServerAddress(), bridgeClient));

        return 0;
    }

    /**
     * @brief Forward message to specified address.
     * 
     * @param mp Message to be forwarded
     * @return int 0 if success, -1 if failure.
     */
    int forwardMessage(MessageParser &mp)
    {
        std::map<std::string, Client *>::iterator remoteServersIterator = remoteServers.begin();
        std::map<std::string, Client *>::iterator remoteServersMapEnd = remoteServers.end();

        std::map<std::string, Client *>::iterator remoteServer = remoteServers.find(mp.getParsedNextAddress());

        if (remoteServer == remoteServersMapEnd)
        {
            return -1;
        }

        return remoteServer->second->writeDataWithoutEncryption(mp.getData(), mp.getDatalen());
    }

    /**
     * @brief Set the method to be called when a new message arrives from a remote server
     * 
     * @param handler Pointer to method which should be called on incoming messages.
     */
    static void onIncomingMessage(IncomingMessageCallback callback) { incomingMessageCallback = callback; };
};

#endif