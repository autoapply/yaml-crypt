const yaml = require('js-yaml');

const crypto = require('./crypto');

/**
 * Supported algorithms
 */
const algorithms = ['fernet:0x80'];

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
function plaintext(str, algorithm = 'fernet:0x80') {
    if (algorithm === 'fernet:0x80') {
        return new PlaintextFernet(str);
    } else {
        throw new Error(`unsupported algorithm: ${algorithm}`);
    }
}

/**
 * Creates an object for encryption
 * @param {string} key The encryption key
 * @param {string} algorithm The algorithm to use
 */
function encrypt(key, algorithm = 'fernet:0x80') {
    return new _Encryption(key, algorithm);
}

class _Encryption {
    constructor(key, algorithm) {
        this.type = _type(key, algorithm);
        this.schema = yaml.Schema.create([this.type]);
    }

    encryptRaw(str) {
        return this.type.represent(str);
    }

    safeDump(obj, opts) {
        opts = opts || {};
        opts.schema = this.schema;
        return yaml.safeDump(obj, opts);
    }
}

/**
 * Creates an object for decryption
 * @param {string} key The decryption key
 * @param {string} algorithm The algorithm to use
 */
function decrypt(key, algorithm = 'fernet:0x80') {
    return new _Decryption(key, algorithm);
}

class _Decryption {
    constructor(key, algorithm) {
        this.type = _type(key, algorithm);
        this.schema = yaml.Schema.create([this.type]);
    }

    decryptRaw(str) {
        return this.type.construct(str);
    }

    safeLoad(str, opts) {
        opts = opts || {};
        opts.schema = this.schema;
        return yaml.safeLoad(str, opts);
    }

    safeLoadAll(str, iterator, opts) {
        opts = opts || {};
        opts.schema = this.schema;
        return yaml.safeLoadAll(str, iterator, opts);
    }
}

function _type(key, algorithm) {
    if (algorithm === 'fernet:0x80') {
        return _fernetType(key);
    } else {
        throw new Error(`unsupported algorithm: ${algorithm}`);
    }
}

function _fernetType(key) {
    return new yaml.Type('!yaml-crypt/fernet:0x80', {
        kind: 'scalar',
        instanceOf: PlaintextFernet,
        resolve: (data) => data !== null,
        construct: (data) => crypto.fernetDecrypt(key, data),
        represent: (data) => crypto.fernetEncrypt(key, data.toString())
    });
}

module.exports.algorithms = algorithms;
module.exports.plaintext = plaintext;
module.exports.PlaintextFernet = PlaintextFernet;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
