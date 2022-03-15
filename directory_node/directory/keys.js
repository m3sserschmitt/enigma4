const fs = require('fs'),
    crypto = require('crypto');

function exportPublicKey({ privateKey, inFormat, outFormat }) {
    const privateKeyObject = crypto.createPrivateKey(privateKey);

    const publicKey = crypto.createPublicKey({
        key: privateKeyObject,
        format: inFormat
    }).export({
        format: outFormat,
        type: 'spki'
    });

    return {
        privateKeyObject,
        publicKey
    }
}

function exportPublicKeyFromFile({ privateKeyPath, inFormat, outFormat }) {
    const privateKey = fs.readFileSync(privateKeyPath);

    return exportPublicKey({
        privateKey,
        inFormat,
        outFormat
    });
}

module.exports = { exportPublicKeyFromFile, exportPublicKey };
