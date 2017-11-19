const yaml = require('js-yaml');

const crypto = require('./crypto');

/**
 * Plain text, unencrypted, using the Fernet cryptography scheme
 */
class PlaintextFernet {
    constructor(msg) {
        this.msg = msg;
    }

    toString() {
        return this.msg;
    }
}

/**
 * Creates an object for encryption
 * @param {string} key The encryption key
 */
function encrypt(key) {
    return new _Encryption(key);
}

class _Encryption {
    constructor(key) {
        this.key = key;
    }

    safeDump(obj, opts) {
        const type = _fernetType(this.key);
        const schema = yaml.Schema.create([type]);
        opts = opts || {};
        opts.schema = schema;
        return yaml.safeDump(obj, opts);
    }
}

/**
 * Creates an object for decryption
 * @param {string} key The decryption key
 */
function decrypt(key) {
    return new _Decryption(key);
}

class _Decryption {
    constructor(key) {
        this.key = key;
    }

    safeLoad(str, opts) {
        const type = _fernetType(this.key);
        const schema = yaml.Schema.create([type]);
        opts = opts || {};
        opts.schema = schema;
        return yaml.safeLoad(str, opts);
    }
}

function _fernetType(key) {
    return new yaml.Type('!yaml-crypt/fernet:128', {
        kind: 'scalar',
        instanceOf: PlaintextFernet,
        resolve: (data) => data !== null,
        construct: (data) => new PlaintextFernet(crypto.fernetDecrypt(key, data)),
        represent: (data) => crypto.fernetEncrypt(key, data.toString())
    });
}

module.exports.Plaintext = PlaintextFernet;
module.exports.PlaintextFernet = PlaintextFernet;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
