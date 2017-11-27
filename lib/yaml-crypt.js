const yaml = require('js-yaml');

const crypto = require('./crypto');

const ALGORITHM_FERNET = 'fernet:0x80';
const DEFAULT_ALGORITHM = ALGORITHM_FERNET;

/**
 * Supported algorithms
 */
const algorithms = [ALGORITHM_FERNET];

/**
 * Plain text, unencrypted
 */
class Plaintext {
    constructor(plaintext, ciphertext = null, algorithm = DEFAULT_ALGORITHM) {
        if (algorithm !== ALGORITHM_FERNET) {
            throw new Error(`unsupported algorithm: ${algorithm}`);
        }
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;
        this.algorithm = algorithm;
    }

    toString() {
        return this.plaintext;
    }
}

/**
 * Cipher text, encrypted
 */
class Ciphertext {
    constructor(ciphertext, algorithm = DEFAULT_ALGORITHM) {
        if (algorithm !== ALGORITHM_FERNET) {
            throw new Error(`unsupported algorithm: ${algorithm}`);
        }
        this.ciphertext = ciphertext;
        this.algorithm = algorithm;
    }

    toString() {
        return this.ciphertext;
    }
}

/**
 * Creates an object for encryption
 * @param {string} key The encryption key
 * @param {object} opts Encryption options
 */
function encrypt(key, opts = {}) {
    return new _Encryption(key, opts);
}

class _Encryption {
    constructor(key, opts) {
        opts = opts || {};
        const algorithm = opts.algorithm || DEFAULT_ALGORITHM;
        const objects = opts.objects;
        const base64 = opts.base64;
        this.type = _type(key, algorithm, objects, base64);
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

    safeDumpAll(objs, opts) {
        opts = opts || {};
        opts.schema = this.schema;
        let str = '';
        for (let idx = 0; idx < objs.length; idx++) {
            if (idx > 0) {
                str += '---\n';
            }
            str += yaml.safeDump(objs[idx], opts);
        }
        return str;
    }
}

/**
 * Creates an object for decryption
 * @param {string} key The decryption key
 * @param {object} opts Decryption options
 */
function decrypt(key, opts = {}) {
    return new _Decryption(key, opts);
}

class _Decryption {
    constructor(key, opts) {
        opts = opts || {};
        const algorithm = opts.algorithm || DEFAULT_ALGORITHM;
        const objects = opts.objects;
        const base64 = opts.base64;
        this.type = _type(key, algorithm, objects, base64);
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

function _type(key, algorithm, objects, base64) {
    if (algorithm === ALGORITHM_FERNET) {
        return _fernetType(key, objects, base64);
    } else {
        throw new Error(`unsupported algorithm: ${algorithm}`);
    }
}

function _fernetType(key, objects, base64) {
    return new yaml.Type('!yaml-crypt/' + ALGORITHM_FERNET, {
        kind: 'scalar',
        instanceOf: Plaintext,
        resolve: (data) => data !== null,
        construct: data => {
            const decrypted = crypto.fernetDecrypt(key, data);
            const decoded = (base64 ? new Buffer(decrypted, 'base64').toString() : decrypted);
            return (objects ? new Plaintext(decoded, data) : decoded);
        },
        represent: data => {
            let encrypted;
            if (data.ciphertext) {
                encrypted = data.ciphertext;
            } else {
                const str = data.toString();
                const encoded = (base64 ? new Buffer(str).toString('base64') : str);
                encrypted = crypto.fernetEncrypt(key, encoded);
            }
            return (objects ? new Ciphertext(encrypted) : encrypted);
        }
    });
}

module.exports.algorithms = algorithms;
module.exports.Plaintext = Plaintext;
module.exports.Ciphertext = Ciphertext;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
