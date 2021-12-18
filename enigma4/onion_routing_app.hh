#ifndef ONION_ROUTING_H
#define ONION_ROUTING_H

#include "../libcryptography/include/cryptography.hh"
#include <map>
#include <list>

#include "app.h"

#include "../net/connection.hh"

#include "network_bridge.hh"


class OnionRoutingApp : public App
{
    static RSA_CRYPTO rsactx;

    static std::string pubkeyfile;
    static std::string privkeyfile;

    static std::string pubkey;
    static std::string address;

    static std::map<std::string, Connection *> localConnections;

    static NetworkBridge *networkBridge;

    OnionRoutingApp(const std::string &pubkey_file, const std::string &privkey_file);
    
    ~OnionRoutingApp()
    {
        CRYPTO::RSA_CRYPTO_free(rsactx);
    }

    /**
     * @brief Connect to another server in the network.
     * 
     * @param host Hostname of foreign host
     * @param port Port number
     * @param pubkeyfile Public key of foreign server.
     * @return int 0 for success, -1 for failure.
     */
    int connectPeer(const std::string &host, const std::string &port, const std::string &pubkeyfile);

    /**
     * @brief Set the up session; All required data is extracted from mp object.
     * 
     * @param mp 
     * @param conn 
     * @return int 
     */
    static int setupSession(MessageParser &mp, Connection *conn);

    /**
     * @brief Checks if message is a handshake. If so, then performs required operations in order
     * to set session ID, client address, encryption keys etc.
     * 
     * @param mp MessageParser containing handshake.
     * @param conn Connection to be set.
     * @return int 0 if success, -1 if failure.
     */
    static int tryHandshake(MessageParser &mp, Connection *conn);
    
    static int action(MessageParser &mp, Connection *conn);

    /**
     * @brief Forward message to next server.
     * 
     * @param mp MessageParser object containing data to be forwarded.
     * @return int int 0 for success, -1 for failure.
     */
    static int forwardMessage(MessageParser &mp);

    /**
     * @brief Redirects all data received from one client.
     * 
     * @param conn
     * @return int 0 for success, -1 for failure.
     */
    static int redirect(Connection *const conn);

    /**
     * @brief For each connected client, a new thread is started.
     * 
     * @return void* 
     */
    static void *newThread(void *);

    /**
     * @brief This method is called when a message from a remote server arrives and
     * destination address could not be found through remote addresses. 
     * 
     * @param mp Message object to be forwarded.
     * @return int 0 if success -1 if failure.
     */
    static int onMessageFromNetworkBridge(MessageParser mp)
    {
        return forwardMessage(mp);
    }

public:
    /**
     * @brief Create a app object
     * 
     * @param pubkey_file Path to local public key file in PEM format.
     * @param privkey_file Path to local private key file in PEM format.
     * @return OnionRoutingApp& reference to newly created object.
     */
    static OnionRoutingApp &createApp(const std::string &pubkey_file, const std::string &privkey_file);

    /**
     * @brief Attach network bridge object used for comunications with remote servers.
     * 
     * @param networkBridge NetworkBridge Object to be used for remote connections.
     */
    void attachNetworkBridge(NetworkBridge *networkBridge)
    {
        this->networkBridge = networkBridge;
        this->networkBridge->onIncomingMessage(forwardMessage);
    }

    /**
     * @brief Connects to all addresses from netfile. The netfile must contain
     * hostnames, ports and paths to corresponding public keys. For example:
     * example1.com 8080 example1_public_key.pem
     * example2.com 8081 example2_public_key.pem
     * ...
     * and so on.
     * 
     * @param netfile Path to netfile.
     * @return int -1 if all connections failed, 1 if some of them failed and 
     * 0 if all connections succeedeed.
     */
    int joinNetwork(const std::string &netfile);

    /**
     * @brief This method is called by Server when a new client connects.
     * It must be a non-blocking method, typically it creates a new thread for 
     * handling the new client.
     * 
     * @param clientsock Socket used to read data from client.
     * @return int -1 if failure, 0 if success.
     */
    int handleClient(Socket *);

    const std::string getAddress() const { return this->address; }
};

#endif