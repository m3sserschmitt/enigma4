'use strict';

const DIRECTORY_NODE_ACTIONS =
{
    add: "add",
    remove: "remove"
};

const PLACEHOLDERS = {
    publicKey: "$rsa-public-key",
    signature: "$rsa-signature"
};

module.exports = { DIRECTORY_NODE_ACTIONS, PLACEHOLDERS };