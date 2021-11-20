#ifndef CLIENT_HH
#define CLIENT_HH

#include "../libcryptography/include/cryptography.hh"

#include "../protocol/message_builder.hh"
#include "../protocol/message_parser.hh"

#include "../onion_routing/connection.hh"

#include "route.hh"

#include "../networking/socket.hh"

class Client
{
    struct listener_data
    {
        Socket *sock;
        RSA_CRYPTO rsactx;
        AES_CRYPTO aesctx;
        std::string clientAddress;
        std::map<std::string, Route *> *routes;
    };

    Socket *sock;
    Route *serv;

    std::map<std::string, Route *> routes;

    std::string pubkey;
    std::string hexaddress;

    RSA_CRYPTO rsactx;

    virtual int setupSocket(const std::string &host, const std::string &port);

    const std::string setupDest(const std::string &keyfile, Route **route, const BYTE *key = 0, const BYTE *id = 0, SIZE keylen = 32, SIZE idlen = 16);

    int handshake(Route *route, bool add_pubkey = true, bool add_all_keys = false);

    static int exitSignal(MessageParser &mp, std::map<std::string, Route *> *routes);
    
    static int setupSessionFromHandshake(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes, AES_CRYPTO aesctx);
    
    static int action(MessageParser &mp, RSA_CRYPTO rsactx, AES_CRYPTO aesctx, std::map<std::string, Route *> *routes);

    static int decryptIncomingMessage(MessageParser &mp, RSA_CRYPTO rsactx, std::map<std::string, Route *> *routes);
    
    static void *dataListener(void *node);

    int writeDest(MessageBuilder &mb, Route *route);

    void cleanupCircuit(Route *route);

    Client(const Client &c);
    
    const Client &operator=(const Client &c);

public:
    Client(const std::string &pubkey, const std::string &privkey);
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
    const std::string getServerAddress() const { return this->serv->getPubkeyHexDigest(); }

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
    const std::string addNode(const std::string &keyfile, const std::string &last_address, bool identify = false, bool add_keys = false, bool make_new_session = false);

    /**
     * @brief Write data to specified address.
     * 
     * @param data Data to be sent.
     * @param datalen Data length in bytes.
     * @param address Destination address.
     * @return int 0 if success, -1 if failure.
     */
    int writeData(const BYTE *data, SIZE datalen, const std::string &address);

    /**
     * @brief Send EXIT message over circuit
     * 
     * @param address Destination address (typically last address in circuit).
     * @return int 0 if success, -1 if failure.
     */
    int exitCircuit(const std::string &address);

    Socket *getSocket() { return this->sock; }
    void setSocket(Socket *s) { this->sock = s; }

    Connection *createConnectionStructure() const
    {
        Socket *new_socket = sock->makeSocketCopy();

        Connection *new_connection = new Connection(new_socket);
        new_connection->setAddress(this->getServerAddress());

        return new_connection;
    }
};

#endif