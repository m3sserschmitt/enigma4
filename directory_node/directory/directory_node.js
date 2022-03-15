'use strict';

const DirectoryRecord = require('./directory_record'),
    NetworkGraph = require('./network_graph'),
    crypto = require('crypto'),
    request = require('request'),
    { EventEmitter } = require('events'),
    { exportPublicKeyFromFile } = require('./keys'),
    { signObject, verifyObjectSignature } = require('./sign');


class DirectoryNode extends EventEmitter {

    constructor({ neighbors, privateKeyPath }) {
        super();
        
        const { privateKeyObject, publicKey } = exportPublicKeyFromFile({
            privateKeyPath,
            inFormat: 'pem',
            outFormat: 'pem'
        });

        this.privateKeyObject = privateKeyObject;
        this.publicKey = publicKey;

        this.localAddress = DirectoryNode.calculateAddress(this.publicKey);
        this.neighbors = neighbors;

        this.networkGraph = new NetworkGraph({
            localAddress: this.localAddress,
            neighbors: Object.keys(neighbors),
            privateKeyObject: this.privateKeyObject,
            publicKey: this.publicKey
        });
    }

    static calculateAddress(publicKey) {
        const keyBytes = crypto.createPublicKey(publicKey).export({
            format: 'der',
            type: 'spki'
        })

        const hash = crypto.createHash('sha256');
        hash.update(keyBytes);

        return hash.digest('hex');
    }

    register(broadcastMessage) {
        if(this.networkGraph.checkAdjacency(broadcastMessage))
        {
            this.emit('exportNeighborhood', this.exportNeighborhood());
        }

        return this.networkGraph.updateAdjacencyList(broadcastMessage);
    }

    exportNeighborhood() {
        return this.networkGraph.getRecord(this.localAddress);
    }

    exportGraph() {
        const signature = signObject({
            object: this.networkGraph.graph,
            privateKeyObject: this.privateKeyObject
        });

        return {
            graph: this.networkGraph.graph,
            localAddress: this.localAddress,
            publicKey: this.publicKey,
            signature
        };
    }

    static verifyGraph(data) {
        const { localAddress, publicKey, signature, graph } = data;

        const calculatedAddress = DirectoryNode.calculateAddress(publicKey);

        if (calculatedAddress != localAddress) {
            return false;
        }

        if (!verifyObjectSignature({
            object: graph,
            publicKey,
            signature
        })) {
            return false;
        }

        return true;
    }

    getGraph() {
        return this.networkGraph;
    }

    setGraph(graph) {
        this.networkGraph = graph;
    }

    hasNeighbors() {
        return Object.keys(this.neighbors).length > 0;
    }

    updateGraph(exportedData) {
        if (!DirectoryNode.verifyGraph(exportedData)) {
            return false;
        }

        this.networkGraph.setGraph(exportedData.graph);
        return true;
    }

    static makeRequest(url) {
        return new Promise((resolve, reject) => {
            request(url, (error, response, body) => {
                if (error) {
                    reject(error);
                }

                if (response.statusCode != 200) {
                    reject('Invalid status code:', response.statusCode);
                }

                resolve(body);
            });
        });
    }

    async requestRemoteGraph(getGraphRoute) {
        const remoteAddresses = Object.keys(this.neighbors);

        for (const remoteAddress of remoteAddresses) {
            const { hostname, port } = this.neighbors[remoteAddress];

            const url = `http://${hostname}:${port}${getGraphRoute}`;

            try {
                console.log(`[+] Get ${url}.`);

                const data = await DirectoryNode.makeRequest(url);

                if (this.updateGraph(JSON.parse(data))) {
                    console.log(`[+] Remote network graph successfully requested from ${hostname}:${port}.`);

                    this.networkGraph.setRecord(DirectoryRecord.generateRecord({
                        address: this.localAddress,
                        neighbors: Object.keys(this.neighbors),
                        privateKeyObject: this.privateKeyObject,
                        publicKey: this.publicKey
                    }));

                    return new Promise((resolve, reject) => {
                        resolve();
                    });
                }

            } catch (error) {
                console.log(`[-] Error when requesting remote network graph from ${hostname}:${port}. Error message: ${error}.`);
            }
        }

        throw "Failed to get remote network graph.";
    }
};

module.exports = DirectoryNode;
