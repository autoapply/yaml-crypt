const URLSafeBase64 = require('urlsafe-base64');
const fernet = require('fernet');

/**
 * Encrypts the message with the given key.
 * @param {string} key Key to use for encryption, must be exactly 32 bits when encoded in UTF-8
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
 * @param {string} key Key to use for decryption, must be exactly 32 bits when encoded in UTF-8
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

module.exports.fernetEncrypt = fernetEncrypt;
module.exports.fernetDecrypt = fernetDecrypt;
