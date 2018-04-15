const yaml = require('js-yaml');

const crypto = require('./crypto');

const ALGORITHM_FERNET = 'fernet:0x80';
const ALGORITHM_BRANCA = 'branca:0xBA';
const DEFAULT_ALGORITHM = ALGORITHM_FERNET;

/**
 * Supported algorithms
 */
const algorithms = [ALGORITHM_FERNET, ALGORITHM_BRANCA];

/**
 * Plain text, unencrypted
 */
class Plaintext {
    constructor(plaintext, ciphertext = null, algorithm = null) {
        if (algorithm && !algorithms.includes(algorithm)) {
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
    constructor(ciphertext, algorithm = null) {
        if (algorithm && !algorithms.includes(algorithm)) {
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
        const objects = opts.objects;
        const base64 = opts.base64;
        this.algorithm = opts.algorithm || DEFAULT_ALGORITHM;
        this.types = _types(key, this.algorithm, objects, base64);
        this.schema = yaml.Schema.create(this.types);
    }

    encryptRaw(str) {
        for (const type of this.types) {
            if (type.algorithm === this.algorithm) {
                return type.represent(str);
            }
        }
        throw new Error('No type found for algorithm: ' + this.algorithm);
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
        const objects = opts.objects;
        const base64 = opts.base64;
        this.types = _types(key, null, objects, base64);
        this.schema = yaml.Schema.create(this.types);
    }

    decryptRaw(str) {
        for (const type of this.types) {
            try {
                return type.construct(str);
            } catch (e) {
                continue;
            }
        }
        throw new Error('No algorithm found to decrypt message!');
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

/**
 * Return an array of custom Yaml types
 * @param {string} key Encryption/decryption key
 * @param {string} defaultAlgorithm Default algorithm
 * @param {boolean} objects Should objects or strings be returned?
 * @param {boolean} base64 Should the strings be base64 encoded?
 */
function _types(key, defaultAlgorithm, objects, base64) {
    defaultAlgorithm = defaultAlgorithm || DEFAULT_ALGORITHM;
    const fernet = _cryptoType(ALGORITHM_FERNET, key, defaultAlgorithm === ALGORITHM_FERNET,
        objects, base64, crypto.fernetEncrypt, crypto.fernetDecrypt);
    const branca = _cryptoType(ALGORITHM_BRANCA, key, defaultAlgorithm === ALGORITHM_BRANCA,
        objects, base64, crypto.brancaEncrypt, crypto.brancaDecrypt);
    return [fernet, branca];
}

function _cryptoType(algorithm, key, isDefault, objects, base64, encrypt, decrypt) {
    const type = new yaml.Type('!yaml-crypt/' + algorithm, {
        kind: 'scalar',
        instanceOf: Plaintext,
        resolve: (data) => data !== null,
        construct: data => {
            const decrypted = decrypt(key, data);
            const decoded = (base64 ? new Buffer(decrypted, 'base64').toString() : decrypted);
            return (objects ? new Plaintext(decoded, data, algorithm) : decoded);
        },
        predicate: data => {
            return data.algorithm === algorithm || (!data.algorithm && isDefault);
        },
        represent: data => {
            let encrypted;
            if (data.ciphertext) {
                encrypted = data.ciphertext;
            } else {
                const str = data.toString();
                const encoded = (base64 ? new Buffer(str).toString('base64') : str);
                encrypted = encrypt(key, encoded);
            }
            return (objects ? new Ciphertext(encrypted) : encrypted);
        }
    });
    type.algorithm = algorithm;
    return type;
}

module.exports.algorithms = algorithms;
module.exports.Plaintext = Plaintext;
module.exports.Ciphertext = Ciphertext;
module.exports.encrypt = encrypt;
module.exports.decrypt = decrypt;
