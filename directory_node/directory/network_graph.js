'use strict';

const DirectoryRecord = require('./directory_record');


class NetworkGraph {

    constructor({ localAddress, neighbors, privateKeyObject, publicKey }) {
        this.graph = new Object;
        this.localAddress = localAddress;
        this.privateKeyObject = privateKeyObject;
        this.publicKey = publicKey;

        this.graph[localAddress] = DirectoryRecord.generateRecord({
            address: this.localAddress,
            neighbors,
            privateKeyObject,
            publicKey
        });
    }

    getGraph() {
        return this.graph;
    }

    setGraph(graph) {
        this.graph = graph;
    }

    parse(networkGraph) {
        this.setGraph(JSON.parse(networkGraph));
    }

    stringify() {
        return JSON.stringify(this.graph);
    }

    setRecord(record) {
        this.graph[record.data.address] = record;
    }

    getRecord(address) {
        return this.graph[address];
    }

    getLocalAdjacencyList() {
        return this.graph[this.localAddress].data.neighbors;
    }

    checkAdjacency(record) {
        const { address, neighbors } = record.data;

        let localAdjacencyList = this.getLocalAdjacencyList();
        let updated = false;

        // remote list contains local address, but local list does not contain remote address;
        if (neighbors.includes(this.localAddress) && !localAdjacencyList.includes(address)) {

            localAdjacencyList.push(address);
            updated = true;

        }
        // remote list does not contain local address, but local list contains remote address
        else if (!neighbors.includes(this.localAddress) && localAdjacencyList.includes(address)) {
            const addressIndex = localAdjacencyList.indexOf(address);

            localAdjacencyList.splice(addressIndex, 1);

            updated = true;
        }

        if (updated) {
            const newRecord = DirectoryRecord.generateRecord({
                address: this.localAddress,
                neighbors: localAdjacencyList,
                privateKeyObject: this.privateKeyObject,
                publicKey: this.publicKey
            });

            this.setRecord(newRecord);
        }

        return updated;
    }

    updateAdjacencyList(record) {
        const { address, uuid } = record.data;

        if (!DirectoryRecord.verifyRecord(record)) {
            return false;
        }

        if (!this.graph[address]) {
            this.graph[address] = record;
            return true;
        }

        const currentUUID = this.graph[address].data.uuid;

        if (currentUUID != uuid) {
            this.graph[address] = record;
            return true;
        }

        return false;
    }
};

module.exports = NetworkGraph;
