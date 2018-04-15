const URLSafeBase64 = require('urlsafe-base64');
const fernet = require('fernet');
const branca = require('branca');

const brancaDefaults = {
    'ts': undefined,
    'nonce': undefined
};

/**
 * Encrypts the message with the given key.
 * @param {string} key Key to use for encryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg String message to encrypt
 * @returns {string} Base64-encoded encrypted string
 */
function fernetEncrypt(key, msg) {
    const secret = new fernet.Secret(URLSafeBase64.encode(Buffer.from(key, 'utf8')));
    const token = new fernet.Token({ secret: secret });
    return token.encode(msg);
}

/**
 * Decrypts the message with the given key.
 * @param {string} key Key to use for decryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg Base64 encoded message to decrypt
 * @returns {string} Plain text string
 */
function fernetDecrypt(key, msg) {
    const secret = new fernet.Secret(URLSafeBase64.encode(Buffer.from(key, 'utf8')));
    const token = new fernet.Token({
        secret: secret,
        token: msg,
        // we currently don't impose any TTL on messages:
        ttl: 0
    });
    return token.decode();
}

/**
 * Encrypts the message with the given key.
 * @param {string} key Key to use for encryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg String message to encrypt
 * @returns {string} Base62-encoded encrypted string
 */
function brancaEncrypt(key, msg) {
    return branca(key).encode(msg, brancaDefaults.ts, brancaDefaults.nonce);
}

/**
 * Decrypts the message with the given key.
 * @param {string} key Key to use for decryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg Base62 encoded message to decrypt
 * @returns {string} Plain text string
 */
function brancaDecrypt(key, msg) {
    const payload = branca(key).decode(msg);
    return payload.toString();
}

module.exports.fernetEncrypt = fernetEncrypt;
module.exports.fernetDecrypt = fernetDecrypt;

module.exports.brancaDefaults = brancaDefaults;
module.exports.brancaEncrypt = brancaEncrypt;
module.exports.brancaDecrypt = brancaDecrypt;
