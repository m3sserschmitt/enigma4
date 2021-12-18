#ifndef CLIENT_HH
#define CLIENT_HH

#include "../libcryptography/include/cryptography.hh"

#include "../net/messages/message_builder.hh"
#include "../net/messages/message_parser.hh"

#include "../net/connection.hh"
#include "../net/network_node.hh"

#include "../net/sockets/socket.hh"

#include "../types/crypto_context.hh"
#include "../types/map_types.hh"

typedef int (*IncomingMessageCallback)(MessageParser &);

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

    NetworkNode *server;

    NodesMap networkNodes;

    CryptoContext cryptoContext;

    IncomingMessageCallback incomingMessageCallback;

    /**
     * @brief Check if message is an exit signal
     * 
     * @param mp Message object to be checked
     * @param nodes Pointer to nodes map to clean corresponding nodes
     * @return int 0 if success, -1 of failure, 1 if message is not an exit signal
     */
    static int exitSignal(MessageParser &mp, NodesMap *nodes);

    /**
     * @brief Check if incoming message is a handshake. If so, get all required data from
     * handshake message and create a new NetworkNode structure
     * 
     * @param mp Message to be cheked
     * @param localCryptoContext Local crypto context used for decryption and verification
     * @param nodes Nodes map to insert newly created NetworkNode structure
     * @return int 0 if success, -1 if failure, 1 if message is not handshake
     */
    static int setupSessionFromIncomingHandshake(MessageParser &mp, CryptoContext *localCryptoContext, NodesMap *nodes);

    /**
     * @brief Process incoming message: try handshake, AES decryption and check for exit signal
     * 
     * @param mp Message to be processed
     * @param localCryptoContext Local crypto context required for RSA decryption in case of handshake message
     * @param nodes Nodes map used to lookup for session ID in case of AES decryption and/or exit signal
     * @return int 0 if no further actions required, -1 if errors encountered, 1 if message needs 
     * further actions (i.e forwarding)
     */
    static int processIncomingMessage(MessageParser &mp, CryptoContext *localCryptoContext, NodesMap *nodes);

    /**
     * @brief Decrypt incoming message
     * 
     * @param mp Message object to be decrypted
     * @param nodes Pointer to nodes map to search for corresponding NetworkNode structure
     * containing required crypto context for decryption
     * @return int 0 if success, -1 if failure, 1 if message is not AES encrypted
     */
    static int decryptIncomingMessage(MessageParser &mp, NodesMap *nodes)
    {
        if (not mp.hasMessageType(MESSAGE_ENC_AES))
        {
            return 1;
        }

        return mp.removeEncryptionLayer(nodes);
    }

    /**
     * @brief Listen for incoming messages
     * 
     * @param node It must be a pointer to a initialized ClientListenerContext structure
     * @return void* This method returns null
     */
    static void *dataListener(void *args);

    /**
     * @brief Initialize local cryptoContext structure, both RSA and AES
     * 
     * @param privkeyfile Path to private key PEM file used to initialize RSA context for decryption
     * and signing
     * @return int 0 if success, -1 if failure 
     */
    int initCryptoContext(const std::string &privkeyfile);

    /**
     * @brief Initialize NetworkNode structure
     * 
     * @param keyfile Public key of destination node
     * @param node If successfull, it contains resulting NetworkNode structure
     * @param key [Optional] Session key. If null, then a randomly generated session key will be used
     * @param id [Optional] Session ID. If null, then a randomly generated session ID will be used
     * @param keylen [Optional] Session key size in bytes, 32 by default
     * @param idlen [Optional] Session ID size in byte, 16 by default
     * @return const std::string 64 bytes string representing address of initialized node
     */
    const std::string setupNetworkNode(const std::string &keyfile, NetworkNode **node, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    virtual void makeSocket()
    {
        this->clientSocket = new Socket();
    }

    /**
     * @brief Send handshake message to a destination node
     * 
     * @param destinationNode Destination node
     * @param identify If true, then client will perform a full handshake (send encrypted public key + message signature).
     * Otherwise, only session ID and session key will be transmitted
     * @return int 0 if success, -1 if failure
     */
    int performHandshake(NetworkNode *destinationNode, bool identify = true);

    /**
     * @brief Write data to a destination node. Multiple encryption layers applied
     * 
     * @param mb Message Object containing data to be transmitted
     * @param destinationNode Destination node
     * @return int Size of transmitted data in bytes, -1 if failure
     */
    int writeDataWithEncryption(MessageBuilder &mb, NetworkNode *destinationNode);

    void cleanupCircuit(NetworkNode *route);

    /*
     * Copy constructor & operator= decrared private in order to prevent a Client object to be copied
    */
    Client(const Client &c);
    const Client &operator=(const Client &c);

protected:
    Socket *clientSocket;

public:
    Client();

    Client(const std::string &pubkeyfile, const std::string &privkeyfile);

    virtual ~Client();

    /**
     * @brief Set the Client Public Key
     * 
     * @param pubkeyfile Path to public key PEM file
     * @return int 0 if success, -1 if failure
     */
    int setClientPublicKey(const std::string &pubkeyfile)
    {
        this->pubkeyPEM = (PLAINTEXT)readFile(pubkeyfile, "rb");
        return KEY_UTIL::getKeyHexDigest(this->pubkeyPEM, this->hexaddress) < 0 ? -1 : 0;
    }

    /**
     * @brief Set the Client Public Key PEM
     * 
     * @param pubkeypem Public key in PEM format
     * @return int 0 if success, -1 if failure
     */
    int setClientPublicKeyPEM(const std::string &pubkeypem)
    {
        this->pubkeyPEM = pubkeypem;
        return KEY_UTIL::getKeyHexDigest(this->pubkeyPEM, this->hexaddress) < 0 ? -1 : 0;
    }

    /**
     * @brief Set the Client Private Key
     * 
     * @param privkeyfile Path to private key PEM file
     * @return int 0 if success, -1 if failure
     */
    int setClientPrivateKey(const std::string &privkeyfile)
    {
        if (this->cryptoContext.rsaInitPrivkeyFile(privkeyfile) < 0)
        {
            return -1;
        }

        if (this->cryptoContext.rsaInitDecryption() < 0)
        {
            return -1;
        }

        if (this->cryptoContext.rsaInitSignature() < 0)
        {
            return -1;
        }

        return 0;
    }

    int setClientPrivateKeyPEM(const std::string &privkeypem)
    {
        if (this->cryptoContext.rsaInitPrivkey(privkeypem) < 0)
        {
            return -1;
        }

        if (this->cryptoContext.rsaInitDecryption() < 0)
        {
            return -1;
        }

        if (this->cryptoContext.rsaInitSignature() < 0)
        {
            return -1;
        }

        return 0;
    }

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
     * @brief If socket not connected, then try to establish a connection to specified address.
     * If socket is already connected to a remote host, then closes existing connection and opens a new one.
     * 
     * @param host Host to connect to
     * @param port Port to connect to
     * @return int 0 if success, -1 if failure
     */
    virtual int connectSocket(const std::string &host, const std::string &port);

    /**
     * @brief Create a connection to specified server.
     * 
     * @param host Server hostname
     * @param port Port number
     * @param keyfile Path to server public key in PEM format.
     * @param startListener If true, the a new thread is started in order to read data from
     * server.
     * @return int 0 if success, -1 if failure.
     */
    int createConnection(const std::string &host, const std::string &port, const std::string &keyfile, bool startListener = true);

    /**
     * @brief Add a new node to a circuit.
     * 
     * @param keyfile Path to node (a server, or other client) public key in PEM format.
     * @param lastAddress Address of last added node into circuit.
     * @param identify If true, then a full handshake is performed (session encryption key, local public key and 
     * digital signature). Otherwise, only a session key is added to handshake message.
     * @param makeNewSession If true, then a new session id is generated (typically when the first node 
     * is added into a circuit).
     * @return const std::string Address of newly added node. 
     */
    const std::string addNode(const std::string &keyfile, const std::string &lastAddress, bool identify = false, bool makeNewSession = false);

    /**
     * @brief Write data to specified address.
     * 
     * @param data Data to be sent.
     * @param datalen Data length in bytes.
     * @param address Destination address.
     * @return int 0 if success, -1 if failure.
     */
    int writeDataWithEncryption(const BYTE *data, SIZE datalen, const std::string &address)
    {
        MessageBuilder mb(data, datalen);
        NetworkNode *route = this->networkNodes[address];

        if (not route)
        {
            return -1;
        }

        return this->writeDataWithEncryption(mb, route);
    }

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
    int sendExitSignal(const std::string &destinationAddress);

    Socket *getSocket() { return this->clientSocket; }

    void setSocket(Socket *s) { this->clientSocket = s; }

    bool isConnected() const { return this->clientSocket->isConnected(); }

    void onIncomingMessage(IncomingMessageCallback callback) { this->incomingMessageCallback = callback; }

    const std::string getSocketCipher() { return this->clientSocket->getCipher(); }
};

#endif