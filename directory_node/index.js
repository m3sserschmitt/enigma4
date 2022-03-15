'use strict';

const net = require('net'),
    fs = require('fs'),
    express = require('express'),
    DirectoryNode = require('./directory/directory_node');

const readConfig = path => JSON.parse(fs.readFileSync(path));


const config = readConfig(process.argv.slice(2)[0]);

const directoryNode = new DirectoryNode({
    neighbors: config.neighbors,
    privateKeyPath: config.privateKey
});

console.log('[+] Connected to local relay address:', directoryNode.localAddress);

const onionRoutingApp = net.connect(config.socketFile);
const app = express();

onionRoutingApp.on('connect', () => {

    if (directoryNode.hasNeighbors()) {

        directoryNode.requestRemoteGraph(config.getGraphRoute).then(() => {
            const neighborhood = directoryNode.exportNeighborhood();

            console.log("[+] Broadcasting local adjacency list ...");

            onionRoutingApp.write(JSON.stringify(neighborhood), () => {
                console.log('[+] Data successfully sent.');
            });
        });
    }
});

onionRoutingApp.on('data', data => {
    const broadcastMessage = data.toString();
    console.log("\n[+] Broadcast message received.");

    if (directoryNode.register(JSON.parse(broadcastMessage))) {
        console.log('[+] Broadcast message registered successfully.');

        onionRoutingApp.write(broadcastMessage);
    }
});

directoryNode.on('exportNeighborhood', neighborhood => {
    console.log('[+] Export neighborhood event received');

    onionRoutingApp.write(JSON.stringify(neighborhood), () => {
        console.log('[+] Data successfully sent.');
    });
});

app.get('/get_network_graph', (req, res) => {
    const networkGraph = directoryNode.exportGraph();

    res.status(200).json({ ...networkGraph });
});

app.listen(config.listenPort, () => {
    console.log('[+] Http server started is listening on port', config.listenPort);
})