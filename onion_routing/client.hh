#ifndef CLIENT_HH
#define CLIENT_HH

#include "../libcryptography/include/cryptography.hh"

#include "../protocol/message_builder.hh"
#include "../protocol/message_parser.hh"

#include "../onion_routing/connection.hh"

#include "route.hh"

#include "../networking/socket.hh"

#include "crypto_context.hh"

typedef int (*IncomingMessageCallback)(MessageParser &);

typedef std::map<std::string, NetworkNode *> NodesMap;

class Client
{
    struct ClientListenerContext
    {
        // socket to receive data from
        Socket *clientSocket;

        // initialized crypto context for cryptographic operations
        CryptoContext *cryptoContext;

        NodesMap *networkNodes;

        // function pointer to be called when new message arrives
        IncomingMessageCallback incomingMessageCallback;
    };

    std::string pubkeyPEM;
    std::string hexaddress;

    Socket *clientSocket;

    NetworkNode *server;

    NodesMap networkNodes;

    CryptoContext cryptoContext;

    IncomingMessageCallback incomingMessageCallback;

    /**
     * @brief Check if message is an exit signal
     * 
     * @param mp Message object to be checked
     * @param nodes Pointer to nodes map to clean corresponding nodes
     * @return int 0 if success, -1 of failure
     */
    static int exitSignal(MessageParser &mp, NodesMap *nodes);

    /**
     * @brief Check if incoming message is a handshake. If so, get all required data from
     * handshake message and create a new NetworkNode structure
     * 
     * @param mp Message to be cheked
     * @param cryptoContext Local crypto context used for decryption and verification
     * @param nodes Nodes map to insert newly created NetworkNode structure
     * @return int 0 if success, -1 if failure
     */
    static int setupSessionFromIncomingHandshake(MessageParser &mp, CryptoContext *cryptoContext, NodesMap *nodes);

    static int action(MessageParser &mp, CryptoContext *cryptoContext, NodesMap *nodes);

    /**
     * @brief Decrypt incoming message
     * 
     * @param mp Message object to be decrypted
     * @param nodes Pointer to nodes map to search for corresponding NetworkNode structure
     * containing required crypto context for decryption
     * @return int 0 if success, -1 if failure
     */
    static int decryptIncomingMessage(MessageParser &mp, NodesMap *nodes);

    static void *dataListener(void *node);

    int initCryptoContext(const std::string &privkeyfile);

    virtual int setupSocket(const std::string &host, const std::string &port);

    const std::string setupNetworkNode(const std::string &keyfile, NetworkNode **node, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    int handshake(NetworkNode *node, bool identify = true);

    int writeDataWithEncryption(MessageBuilder &mb, NetworkNode *route);

    void cleanupCircuit(NetworkNode *route);

    Client(const Client &c);

    const Client &operator=(const Client &c);

public:
    Client(const std::string &pubkeyfile, const std::string &privkeyfile);
    ~Client();

    /**
     * @brief Get the client hexaddress.
     * 
     * @return const std::string& Client local address.
     */
    const std::string &getClientHexaddress() const { return this->hexaddress; }

    /**
     * @brief Get the server address.
     * 
     * @return const std::string Server address.
     */
    const std::string getServerAddress() const { return this->server->getPubkeyHexDigest(); }

    /**
     * @brief Create a connection to specified server.
     * 
     * @param host Server hostname
     * @param port Port number
     * @param keyfile Path to server public key in PEM format.
     * @param start_listener If true, the a new thread is started in order to read data from
     * server.
     * @return int 0 if success, -1 if failure.
     */
    int createConnection(const std::string &host, const std::string &port, const std::string &keyfile, bool start_listener = true);

    /**
     * @brief Add a new node to a circuit.
     * 
     * @param keyfile Path to node (a server, or other client) public key in PEM format.
     * @param last_address Address of last added node into circuit.
     * @param identify If true, then a full handshake is performed (session encryption key, local public key and 
     * digital signature). Otherwise, only a session key is added to handshake message.
     * @param make_new_session If true, then a new session id is generated (typically when the first node 
     * is added into a circuit).
     * @return const std::string Address of newly added node. 
     */
    const std::string addNode(const std::string &keyfile, const std::string &last_address, bool identify = false, bool make_new_session = false);

    /**
     * @brief Write data to specified address.
     * 
     * @param data Data to be sent.
     * @param datalen Data length in bytes.
     * @param address Destination address.
     * @return int 0 if success, -1 if failure.
     */
    int writeDataWithEncryption(const BYTE *data, SIZE datalen, const std::string &address);

    /**
     * @brief This method sends data directly to server, no encryption layer applied.
     * 
     * @param mp Message object to be sent
     * @return int 0 if success, -1 if failure.
     */
    int writeDataWithoutEncryption(const BYTE *data, SIZE datalen)
    {
        return this->clientSocket->writeData(data, datalen);
    }

    /**
     * @brief Send EXIT message over circuit
     * 
     * @param address Destination address (typically last address in circuit).
     * @return int 0 if success, -1 if failure.
     */
    int exitCircuit(const std::string &address);

    Socket *getSocket() { return this->clientSocket; }

    void setSocket(Socket *s) { this->clientSocket = s; }

    bool isConnected() const { return this->clientSocket->isConnected(); }

    void onIncomingMessage(IncomingMessageCallback callback) { this->incomingMessageCallback = callback; }
};

#endif