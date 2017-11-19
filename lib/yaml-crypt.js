const yaml = require('js-yaml');

const crypto = require('./crypto');

/**
 * Supported algorithms
 */
const algorithms = ['fernet:128'];

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
 * Creates a plaintext object that can be encrypted
 * @param {string} str The string value of the object
 * @param {string} algorithm The algorithm to use
 */
function plaintext(str, algorithm = 'fernet:128') {
    if (algorithm === 'fernet:128') {
        return new PlaintextFernet(str);
    } else {
        throw new Error(`unsupported algorithm: ${algorithm}`);
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
        const type = _fernetType([this.key]);
        const schema = yaml.Schema.create([type]);
        opts = opts || {};
        opts.schema = schema;
        return yaml.safeDump(obj, opts);
    }
}

/**
 * Creates an object for decryption
 * @param {string[]} keys The decryption keys
 */
function decrypt(keys) {
    return new _Decryption(keys);
}

class _Decryption {
    constructor(keys) {
        this.keys = keys;
    }

    safeLoad(str, opts) {
        const type = _fernetType(this.keys);
        const schema = yaml.Schema.create([type]);
        opts = opts || {};
        opts.schema = schema;
        return yaml.safeLoad(str, opts);
    }

    safeLoadAll(str, iterator, opts) {
        const type = _fernetType(this.keys);
        const schema = yaml.Schema.create([type]);
        opts = opts || {};
        opts.schema = schema;
        return yaml.safeLoadAll(str, iterator, opts);
    }
}

function _fernetType(keys) {
    return new yaml.Type('!yaml-crypt/fernet:128', {
        kind: 'scalar',
        instanceOf: PlaintextFernet,
        resolve: (data) => data !== null,
        construct: (data) => _tryDecrypt(keys, data, crypto.fernetDecrypt),
        represent: (data) => crypto.fernetEncrypt(keys[0], data.toString())
    });
}

function _tryDecrypt(keys, data, worker) {
    for (const key of keys) {
        try {
            return worker(key, data);
        } catch (e) {
            continue;
        }
    }
    throw new Error('No matching key to decrypt the given data!');
}

module.exports.algorithms = algorithms;
module.exports.plaintext = plaintext;
module.exports.PlaintextFernet = PlaintextFernet;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
