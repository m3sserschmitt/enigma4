const DirectoryRecord = require('./directory/directory_record'),
    DirectoryNode = require('./directory/directory_node'),
    {exportPublicKey, exportPublicKeyFromFile} = require('./directory/keys');
// const record = DirectoryRecord.generateRecord('test-address', ['neighbor1', 'neighbor-2'], '../keys/server_private1.pem');

// console.log(DirectoryRecord.verifyRecord(record));

const directoryNode = new DirectoryNode({
    neighbors: ['neighbor-address-1', 'neighbor-address-2'],
    privateKeyPath: '../keys/server_private1.pem'
});

const graph = directoryNode.exportGraph();

console.log(DirectoryNode.verifyGraph(graph));

// console.log(DirectoryNode.calculateLocalAddress('../keys/server_private1.pem'));

// console.log(exportPublicKeyFromFile({
//     privateKeyPath: "../keys/server_private1.pem",
//     inFormat: 'pem',
//     outFormat: 'der'
// }));