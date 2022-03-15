const crypto = require('crypto');

function signObject({ object, privateKeyObject }) {
    const sign = crypto.createSign('SHA256');

    sign.write(JSON.stringify(object));
    sign.end();

    return sign.sign(privateKeyObject, 'base64');
}

function verifySignature({ data, signature, publicKey }) {

    const verify = crypto.createVerify('SHA256');

    verify.write(data);
    verify.end();
    
    return verify.verify(publicKey, signature, 'base64');
}

function verifyObjectSignature({ object, signature, publicKey }) {
    
    return verifySignature({
        data: JSON.stringify(object),
        publicKey,
        signature
    });
}

module.exports = { signObject, verifySignature, verifyObjectSignature };