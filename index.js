'use strict';

const tls = require('tls'),
    net = require('net'),
    fs = require('fs'),
    { spawn } = require('child_process');

const readConfig = path => JSON.parse(fs.readFileSync(path));

const commandLineArguments = process.argv.slice(2);
const serverConfig = readConfig(commandLineArguments[0]);

fs.unlinkSync(serverConfig.socketFile);

const enigmaSubprocess = spawn(serverConfig.enigma, [
    "-pubkey", serverConfig.publicKey,
    "-privkey", serverConfig.privateKey,
    "-host", serverConfig.socketFile
], {
    stdio: [
        0, // Use parent's stdin for child.
        'pipe', // Pipe child's stdout to parent.
        'pipe'
    ]
});

console.log('[+] Enigma subprocess started; PID: ', enigmaSubprocess.pid);

enigmaSubprocess.on('exit', code => {
    console.log('[+] Enigma subprocess exited with code', code);
});

enigmaSubprocess.on('error', () => {
    console.log('[-] Errors occurred when started enigma subprocess');
});

enigmaSubprocess.stdout.on('data', data => {
    console.log(data.toString());
});

const serverOptions = {
    key: fs.readFileSync(serverConfig.privateKey),
    cert: fs.readFileSync(serverConfig.certificate)
};

var server = tls.createServer(serverOptions, socket => {

    socket.on('data', data => {
        let ipcSocket = net.createConnection(serverConfig.socketFile);

        ipcSocket.write(data);

        ipcSocket.on('data', buffer => {
            if (!socket.destroyed) {
                socket.write(buffer);
            }
        });

        socket.on('data', buffer => {
            if (!socket.destroyed) {
                ipcSocket.write(buffer);
            }
        });
    });
});

// Start listening on a specific port and address
server.listen(serverConfig.listenPort, serverConfig.listenAddress, () => {
    console.log("[+] Server is listening on", serverConfig.listenAddress, ":", serverConfig.listenPort);
});

// When an error occurs, show it.
server.on('error', error => {
    console.error(error);

    // Close the connection after the error occurred.
    server.destroy();
});