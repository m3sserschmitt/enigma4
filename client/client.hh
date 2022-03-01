#ifndef CLIENT_HH
#define CLIENT_HH

#include "../libcryptography/include/cryptography.hh"

#include "../net/messages/message_builder.hh"
#include "../net/messages/message_parser.hh"

#include "../net/connection.hh"
#include "../net/network_node.hh"

#include "../net/sockets/socket.hh"

#include "../types/map_types.hh"
#include "../types/callbacks.hh"

class Client
{
    typedef struct   
     {
        /**
         * @brief Socket to receive data from
         *
         */
        Socket *clientSocket;

        /**
         * @brief Initialized RSA context for incoming session-establishing messages decryption
         *
         */
        RSA_CRYPTO rsactx;

        /**
         * @brief Initialized AES context for incoming messages decryption
         *
         */
        AES_CRYPTO aesctx;

        /**
         * @brief NetworkNode structures map
         *
         */
        NodesMap *networkNodes;

        /**
         * @brief Pointer to function to be called when new message arrives
         *
         */
        OnMessageReceivedCallback messageReceivedCallback;

        /**
         * @brief Pointer to function to be called when new session established from remote peer
         *
         */
        OnNewSessionSetCallback newSessionSetCallback;

        /**
         * @brief Pointer to function to be called when EXIT signal received
         *
         */
        OnSessionClearedCallback sessionClearedCallback;

        /**
         * @brief Object used for handling incoming message
         * 
         */
        MessageParser mp;

        /**
         * @brief Pointer to listener thread
         *
         */
        pthread_t *listenerThread;
    } ClientListenerContext;

    /**
     * @brief Status returned by processIncomingMessage method
     *
     */
    enum MessageProcessingStatus
    {
        /**
         * @brief Status code returned when errors occurred during processing
         *
         */
        PROCESSING_ERROR = -1,

        /**
         * @brief Status code returned when message successfully processed and no further actions required
         *
         */
        PROCESSING_DONE = 0,

        /**
         * @brief Status code returned when new session was set
         *
         */
        SESSION_SET = 1,

        /**
         * @brief Status code returned when incoming message is not AES encrypted
         *
         */
        DECRYPTION_FAILED = 2,

        /**
         * @brief Status code returned when EXIT signal received
         *
         */
        SESSION_CLEARED = 3,

        /**
         * @brief Status code when new message received and successfully decrypted
         *
         */
        MESSAGE_DECRYPTED_SUCCESSFULLY = 4,
    };

    /**
     * @brief Client loaded public key in PEM format
     *
     */
    std::string pubkeypem;

    /**
     * @brief Client public key SHA256
     *
     */
    std::string hexaddress;

    /**
     * @brief Pointer to the first node in the circuit, also called the Guard Node
     *
     */
    NetworkNode *guardNode;

    /**
     * @brief Circuit Map
     *
     */
    NodesMap networkNodes;

    /**
     * @brief RSA context for incoming session messages decryption
     *
     */
    RSA_CRYPTO rsactx;

    /**
     * @brief AES context for messages encryption/decryption
     *
     */
    AES_CRYPTO aesctx;

    /**
     * @brief Pointer to function to be called when new message received
     *
     */
    OnMessageReceivedCallback messageReceivedCallback;

    /**
     * @brief Pointer to function to be called when new session established
     *
     */
    OnNewSessionSetCallback newSessionSetCallback;

    /**
     * @brief Pointer to function to be called when EXIT signal received and session cleared
     *
     */
    OnSessionClearedCallback sessionClearedCallback;

    /**
     * @brief Pointer to listener thread
     *
     */
    pthread_t *listenerThread;

    /**
     * @brief Listener context structure containing required crypto contexts & pointers to callback functions
     * 
     */
    ClientListenerContext *listenerContext;

    /**
     * @brief Initialize RSA context for both decryption and signing
     *
     * @return int 0 if success, -1 if failure
     */
    int initRSA_DecryptionAndSigning()
    {
        if (CRYPTO::RSA_init_ctx(this->rsactx, DECRYPT) < 0)
        {
            return -1;
        }

        if (CRYPTO::RSA_init_ctx(this->rsactx, SIGN) < 0)
        {
            return -1;
        }

        return 0;
    }

    /**
     * @brief Check if message is an exit signal
     *
     * @param mp Message object to be checked
     * @param nodes Pointer to nodes map to clean corresponding nodes
     * @return int 0 if success, -1 of failure, 1 if message is not an exit signal
     */
    static int exitSignal(MessageParser &mp, NodesMap *nodes);

    /**
     * @brief If message is handshake, then setup a new NetworkNode structure.
     *
     * @param mp Message to be cheked
     * @param rsactx Initialized RSA context for session message decryption
     * @param aesctx Initialized AES context to be set for decryption into newly created NetworkNode structure
     * @param networkNodes Nodes map in which newly created NetworkNode should be inserted
     * @return int 0 is success, -1 if errors occurred, 1 if message is not add session request
     */
    static int setupSessionFromIncomingHandshake(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, NodesMap *networkNodes);

    /**
     * @brief Process incoming message: try handshake, AES decryption and check for exit signal
     *
     * @param mp Message to be processed
     * @param rsactx Initialized RSA context for session message decryption
     * @param aesctx Initialized AES context to be set for decryption into newly created NetworkNode structure
     * @param nodes Nodes map used to lookup for session ID in case of AES decryption and/or exit signal or intering newly
     * created NetworkNode stucture in case of new session established
     * @return int 0 if no further actions required, -1 if errors encountered, 1 if message needs
     * further actions (e.g. calls to messageReceivedCallback or newSessionSetCallback)
     */
    static MessageProcessingStatus processIncomingMessage(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, NodesMap *networkNodes);

    /**
     * @brief Decrypt incoming message
     *
     * @param mp Message object to be decrypted
     * @param nodes Pointer to nodes map to search for corresponding NetworkNode structure
     * containing required crypto context for decryption
     * @return int 0 if success, -1 if failure, 1 if message is cannot be decrypted
     */
    static int decryptIncomingMessage(MessageParser &mp, NodesMap *nodes)
    {
        if (not mp.hasAtLeastOneType(MESSAGE_ENC_AES))
        {
            return 1;
        }

        return mp.removeEncryptionLayer(nodes);
    }

    /**
     * @brief Listener Thread function
     *
     * @param node It must be a pointer to a initialized ClientListenerContext structure
     * @return void* This method returns null
     */
    static void *dataListener(void *args);

    /**
     * @brief Initialize RSA & AES structures
     *
     * @param privkeyfile Path to private key in PEM format to be used for RSA structure initialization
     * @return int 0 if success, -1 if failure
     */
    int initCrypto(const std::string &privkeyfile);

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
    const std::string setupNetworkNode(const std::string &keyfile, NetworkNode **node, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = SESSION_KEY_SIZE, SIZE idlen = SESSION_ID_SIZE);

    /**
     * @brief Create new Socket object for data reading & writing
     *
     */
    virtual void makeSocket() { this->clientSocket = new Socket(); }

    /**
     * @brief Send handshake message to a destination node
     *
     * @param destinationNode Destination node
     * @return int 0 if success, -1 if failure
     */
    int addNewSession(NetworkNode *destinationNode)
    {
        if (not destinationNode)
        {
            return -1;
        }

        MessageBuilder mb;
        mb.addSessionMessage(destinationNode->getId(), destinationNode->getSessionKey(), destinationNode->getRSA());

        return this->writeDataWithEncryption(mb, destinationNode) < 0 ? -1 : 0;
    }

    /**
     * @brief Perform Phase One handshake: send handshake message containing session key and wait for server response containing session id & test phrase
     *
     * @param encrctx RSA context initialized with corresponding server public key for session key encryption
     * @param aesctx Initialized AES context for handshake message encryption
     * @param sessionId If successful, sessionId will point to returned session Id from server
     * @param test If successful, test will point to returned test phrase from server
     * @return int 0 is success, -1 if errors occurred
     */
    int guardHandhsakePhaseOne(RSA_CRYPTO encrctx, AES_CRYPTO aesctx, BYTES *sessionId, BYTES *test);

    /**
     * @brief Perform Phase Two handshake: sign test phrase returned from phase one and send back to server for authentication
     *
     * @param sessionId Session id returned from phase one
     * @param test Test phrase returned from phase one
     * @return int 0 is success, -1 if errors occurred
     */
    int guardHandshakePhaseTwo(const BYTE *sessionId, const BYTE *test);

    /**
     * @brief Perform handshake, phase one + phase two
     *
     * @param guardNode Pointer to guard node structure
     * @return int 0 if success, -1 if errors occurred
     */
    int performGuardHandshake(NetworkNode *guardNode);

    /**
     * @brief Write data to a destination node. Multiple encryption layers applied
     *
     * @param mb Message Object containing data to be transmitted
     * @param destinationNode Destination node
     * @return int Size of transmitted data in bytes, -1 if failure
     */
    int writeDataWithEncryption(MessageBuilder &mb, NetworkNode *destinationNode);

    /**
     * @brief Cleanup all NetworkNode structure from circuit
     *
     * @param lastNode Last node in circuit
     */
    void cleanupCircuit(NetworkNode *lastNode)
    {
        NetworkNode *next;
        for (NetworkNode *p = lastNode->getPrevious(); p; p = p->getPrevious())
        {
            next = p->getNext();

            if (next)
            {
                this->networkNodes.erase(next->getPubkeyHexDigest());
                delete next;
                next = 0;
            }
        }
    }

    /**
     * @brief Get the Guard Session Key
     *
     * @return const BYTE* guard session key
     */
    const BYTE *getGuardSessionKey() const
    {
        BYTES sessionKey = 0;

        if (CRYPTO::AES_read_key(this->guardNode->getAES(), SESSION_ID_SIZE, &sessionKey) < 0)
        {
            delete[] sessionKey;
            sessionKey = 0;

            return 0;
        }

        return sessionKey;
    }

    /**
     * @brief Get the Guard Session Id
     *
     * @return const BYTE* guard session id
     */
    const BYTE *getGuardSessionId() const
    {
        BYTES sessionId = new BYTE[SESSION_KEY_SIZE + 1];

        if (not sessionId)
        {
            return 0;
        }

        memcpy(sessionId, this->guardNode->getId(), SESSION_ID_SIZE);

        return sessionId;
    }

    /*
     * Copy constructor & operator= decrared private in order to prevent a Client object to be copied
     */
    Client(const Client &c);
    const Client &operator=(const Client &c);

protected:
    /**
     * @brief Socket object for reading & writing data
     *
     */
    Socket *clientSocket;

public:
    /**
     * @brief Construct a new Client object
     *
     */
    Client()
    {
        this->guardNode = 0;
        this->clientSocket = 0;
        this->listenerThread = 0;
        this->listenerContext = 0;
        this->newSessionSetCallback = 0;
        this->sessionClearedCallback = 0;
        this->messageReceivedCallback = 0;

        this->aesctx = CRYPTO::AES_CRYPTO_new();
        this->rsactx = CRYPTO::RSA_CRYPTO_new();
    }

    /**
     * @brief Construct a new Client object
     *
     * @param pubkeyfile Path to public key file in PEM format
     * @param privkeyfile Path to private key file in PEM format
     */
    Client(const std::string &pubkeyfile, const std::string &privkeyfile)
    {
        this->guardNode = 0;
        this->clientSocket = 0;
        this->listenerThread = 0;
        this->listenerContext = 0;
        this->newSessionSetCallback = 0;
        this->sessionClearedCallback = 0;
        this->messageReceivedCallback = 0;

        this->aesctx = CRYPTO::AES_CRYPTO_new();
        this->rsactx = CRYPTO::RSA_CRYPTO_new();

        this->setClientPublicKey(pubkeyfile);
        this->initCrypto(privkeyfile);
    }

    /**
     * @brief Destroy the Client object
     *
     */
    virtual ~Client();

    /**
     * @brief Set Client Public Key
     *
     * @param pubkeyfile Path to public key file in PEM file
     * @return int 0 if success, -1 if failure
     */
    int setClientPublicKey(const std::string &pubkeyfile)
    {
        this->pubkeypem = (PLAINTEXT)readFile(pubkeyfile, "rb");
        return KEY_UTIL::getKeyHexDigest(this->pubkeypem, this->hexaddress) < 0 ? -1 : 0;
    }

    /**
     * @brief Set Client Public Key PEM
     *
     * @param pubkeypem Public key in PEM format
     * @return int 0 if success, -1 if failure
     */
    int setClientPublicKeyPEM(const std::string &pubkeypem)
    {
        this->pubkeypem = pubkeypem;
        return KEY_UTIL::getKeyHexDigest(this->pubkeypem, this->hexaddress) < 0 ? -1 : 0;
    }

    /**
     * @brief Set Client Private Key and initialize RSA context for both decryption and signing
     *
     * @param privkeyfile Path to private key file in PEM file
     * @return int 0 if success, -1 if failure
     */
    int loadClientPrivateKey(const std::string &privkeyfile)
    {
        if (CRYPTO::RSA_init_key_file(privkeyfile, 0, 0, PRIVATE_KEY, this->rsactx) < 0)
        {
            return -1;
        }

        return this->initRSA_DecryptionAndSigning();
    }

    /**
     * @brief Set the Client Private Key & initialize RSA context for both decryption & signing
     *
     * @param privkeypem Private key in PEM format
     * @return int 0 if success, -1 if errors occurred
     */
    int loadClientPrivateKeyPEM(const std::string &privkeypem)
    {
        if (CRYPTO::RSA_init_key(privkeypem, 0, 0, PRIVATE_KEY, this->rsactx) < 0)
        {
            return -1;
        }

        return initRSA_DecryptionAndSigning();
    }

    /**
     * @brief Get the client hexaddress.
     *
     * @return const std::string& Client local address.
     */
    const std::string &getClientHexaddress() const { return this->hexaddress; }

    /**
     * @brief Get the guard address.
     *
     * @return const std::string guard address.
     */
    const std::string getGuardAddress() const { return this->guardNode->getPubkeyHexDigest(); }

    /**
     * @brief Create new connection. If socket already connected, then close old connection and open a new one
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
    int createConnection(const std::string &host, const std::string &port, const std::string &keyfile);

    /**
     * @brief Close active connection
     *
     */
    void closeConnection()
    {
        if (this->clientSocket)
        {
            this->clientSocket->closeSocket();
        }
    }

    /**
     * @brief Start client listener for incoming messages processing
     *
     * @return int 0 if success, -1 if errors occurred
     */
    int startListener();

    /**
     * @brief Stop client listener
     *
     * @return int 0 if success, -1 if errors occurred
     */
    int stopListener()
    {
        if (this->listenerThread)
        {
            return pthread_cancel(*this->listenerThread) == 0 ? 0 : -1;
        }

        return -1;
    }

    /**
     * @brief Stop client listener and for its execution to end
     *
     * @return int 0 is success, -1 if errors occurred
     */
    int listenerStopWait()
    {
        if (this->stopListener() < 0)
        {
            return -1;
        }

        return pthread_join(*this->listenerThread, 0) == 0 ? 0 : -1;
    }

    /**
     * @brief Add a new node to a circuit.
     *
     * @param keyfile Path to node public key in PEM format.
     * @param lastAddress Address of last added node into circuit
     * @param makeNewSession If true, then a new session id is generated
     * @return const std::string Address of newly added node.
     */
    const std::string addNode(const std::string &keyfile, const std::string &lastAddress, bool newSessionId = false);

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
    int sendExitSignal(const std::string &destinationAddress)
    {
        NetworkNode *destinationNode = this->networkNodes[destinationAddress];

        if (not destinationNode)
        {
            return -1;
        }

        MessageBuilder mb;
        mb.makeExitSignal();

        int result = this->writeDataWithEncryption(mb, destinationNode);

        this->cleanupCircuit(destinationNode);

        return result;
    }

    /**
     * @brief Get the Socket object
     *
     * @return Socket* client socket object used for reading & writing data
     */
    const Socket *getSocket() const { return this->clientSocket; }

    /**
     * @brief Check if client is connected to any host
     *
     * @return true if client is connected
     * @return false if client not connected
     */
    bool isConnected() const { return this->clientSocket->isConnected(); }

    /**
     * @brief Set function to be called when new message arrives
     *
     * @param callback Pointer to function to be called when new message arrives
     */
    void onMessageReceived(OnMessageReceivedCallback callback) { this->messageReceivedCallback = callback; }

    /**
     * @brief Set function to be called when new session from remote peers established
     *
     * @param callback Pointer to function to be called when new session established
     */
    void onSessionSet(OnNewSessionSetCallback callback) { this->newSessionSetCallback = callback; }

    /**
     * @brief Set function to be called when EXIT signal received and session cleared
     * 
     * @param callback Pointer to function to be called when session cleared
     */
    void onSessionCleared(OnSessionClearedCallback callback) { this->sessionClearedCallback = callback; }

    /**
     * @brief Get the TLS Socket Cipher
     *
     * @return const std::string information about TLS cipher used for comunications
     */
    const std::string getSocketCipher() const { return this->clientSocket->getCipher(); }

    /**
     * @brief Create Connection Object representing connection to Guard Node
     *
     * After this method is called, current Client Object cannot be used for reading or writing data
     *
     * @return Connection*
     */
    Connection *getGuardConnection()
    {
        Connection *conn = new Connection();

        if (not conn)
        {
            return 0;
        }

        const BYTE *sessionId = this->getGuardSessionId();
        const BYTE *sessionKey = this->getGuardSessionKey();

        conn->setSocket(this->clientSocket);
        conn->addSession(sessionId, sessionKey);
        conn->setAddress(this->guardNode->getPubkeyHexDigest());

        this->clientSocket = 0;

        delete[] sessionId;
        delete[] sessionKey;

        sessionId = 0;
        sessionKey = 0;

        return conn;
    }
};

#endif