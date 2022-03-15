'use strict';

const uuid = require('uuid'),
    crypto = require('crypto');


class DirectoryRecord {

    static signRecord({ record, privateKeyObject, publicKey }) {
        const sign = crypto.createSign('SHA256');

        sign.write(JSON.stringify(record.data));
        sign.end();

        const signature = sign.sign(privateKeyObject, 'base64');

        return {
            data: record.data,
            publicKey,
            signature
        };
    }

    static generateRecord({ address, neighbors, privateKeyObject, publicKey }) {

        let record = {
            data: {
                uuid: uuid.v4(),
                address,
                neighbors
            }
        }

        return DirectoryRecord.signRecord({ record, privateKeyObject, publicKey });

    };

    static verifyRecord(record) {
        const data = record.data;
        const publicKey = record.publicKey;
        const signature = record.signature;

        const verify = crypto.createVerify('SHA256');

        verify.write(JSON.stringify(data));
        verify.end();

        return verify.verify(publicKey, signature, 'base64');
    }
}

module.exports = DirectoryRecord;