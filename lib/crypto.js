const crypto = require("crypto");

const URLSafeBase64 = require("urlsafe-base64");
const fernet = require("fernet");
const branca = require("branca");

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const base62 = require("base-x")(BASE62);

const ALGORITHM_FERNET = "fernet:0x80";
const ALGORITHM_BRANCA = "branca:0xBA";

const DEFAULT_ALGORITHM = ALGORITHM_FERNET;

const algorithmHandlers = {
  [ALGORITHM_FERNET]: {
    generateKey: fernetGenerateKey,
    encrypt: fernetEncrypt,
    decrypt: fernetDecrypt
  },
  [ALGORITHM_BRANCA]: {
    generateKey: brancaGenerateKey,
    encrypt: brancaEncrypt,
    decrypt: brancaDecrypt
  }
};

const algorithms = [ALGORITHM_FERNET, ALGORITHM_BRANCA];

const __brancaDefaults = {
  ts: undefined,
  nonce: undefined
};

/**
 * Check if the given data is a valid token
 * @param {string|Buffer} data Data to check
 * @returns {boolean} If the given data is a valid token
 */
function isToken(data) {
  if (typeof data === "string") {
    if (data.length > 2) {
      if (data[0] === "g" && data[1].match(/[a-zA-Z0-9]/)) {
        return Buffer.from(data.substr(0, 2), "base64")[0] === 0x80;
      } else {
        const str = data.trimRight();
        if (str.match(/^[a-zA-Z0-9]+$/)) {
          const result = base62.decodeUnsafe(str);
          return result != null && result[0] === 0xba;
        }
      }
    }
  } else if (Buffer.isBuffer(data)) {
    if (data.length > 2 && data[0] === "g".charCodeAt(0)) {
      const buf = Buffer.from(data.slice(0, 2).toString("ascii"), "base64");
      if (buf[0] === 0x80) {
        return true;
      }
    }
    try {
      const str = data.toString("ascii").trimRight();
      const result = base62.decodeUnsafe(str);
      return result != null && result[0] === 0xba;
    } catch (e) {
      // ignore error!
    }
  }
  return false;
}

/**
 * Generate a new random key
 * @param {string} algorithm Encryption algorithm
 * @returns {string} Randomly generated key
 */
function generateKey(algorithm) {
  return handler(algorithm).generateKey();
}

/**
 * Encrypt the message with the given key.
 * @param {string} algorithm Encryption algorithm
 * @param {string} key Key to use for encryption
 * @param {string} msg String message to encrypt
 * @returns {string} Base64-encoded encrypted string
 */
function encrypt(algorithm, key, msg) {
  return handler(algorithm).encrypt(key, msg);
}

/**
 * Decrypt the message with the given key.
 * @param {string} algorithm Decryption algorithm
 * @param {string} key Key to use for decryption
 * @param {string} msg Base64 encoded message to decrypt
 * @returns {string} Plain text string
 */
function decrypt(algorithm, key, msg) {
  if (msg == null) {
    throw new Error("message is null!");
  } else if (typeof msg !== "string") {
    throw new Error(`invalid type for message: ${typeof msg}`);
  }
  return handler(algorithm).decrypt(key, msg);
}

function handler(algorithm) {
  if (!algorithm) {
    return algorithmHandlers[DEFAULT_ALGORITHM];
  }
  let h = algorithmHandlers[algorithm];
  if (h != null) {
    return h;
  }
  for (const a of algorithms) {
    if (a.startsWith(`${algorithm}:`)) {
      return algorithmHandlers[a];
    }
  }
  throw new Error(`unknown algorithm: ${algorithm}`);
}

/**
 * Generate a new key that can be used for Fernet cryptography.
 * @returns {string} Randomly generated key
 */
function fernetGenerateKey() {
  return generateRandomBase64(32);
}

/**
 * Encrypt the message with the given key.
 * @param {string} key Key to use for encryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg String message to encrypt
 * @returns {string} Base64-encoded encrypted string
 */
function fernetEncrypt(key, msg) {
  const secret = new fernet.Secret(
    URLSafeBase64.encode(Buffer.from(key, "utf8"))
  );
  const token = new fernet.Token({ secret: secret });
  return token.encode(msg);
}

/**
 * Decrypt the message with the given key.
 * @param {string} key Key to use for decryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg Base64 encoded message to decrypt
 * @returns {string} Plain text string
 */
function fernetDecrypt(key, msg) {
  const secret = new fernet.Secret(
    URLSafeBase64.encode(Buffer.from(key, "utf8"))
  );
  const token = new fernet.Token({
    secret: secret,
    token: msg,
    // we currently don't impose any TTL on messages:
    ttl: 0
  });
  return token.decode();
}

/**
 * Generate a new key that can be used for Branca cryptography.
 * @returns {string} Randomly generated key
 */
function brancaGenerateKey() {
  return generateRandomBase64(32);
}

/**
 * Encrypt the message with the given key.
 * @param {string} key Key to use for encryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg String message to encrypt
 * @returns {string} Base62-encoded encrypted string
 */
function brancaEncrypt(key, msg) {
  const bytes = Buffer.from(key);
  return branca(bytes).encode(msg, __brancaDefaults.ts, __brancaDefaults.nonce);
}

/**
 * Decrypt the message with the given key.
 * @param {string} key Key to use for decryption, must be exactly 32 bytes when encoded in UTF-8
 * @param {string} msg Base62 encoded message to decrypt
 * @returns {string} Plain text string
 */
function brancaDecrypt(key, msg) {
  const bytes = Buffer.from(key);
  const payload = branca(bytes).decode(msg);
  return payload.toString();
}

function generateRandomBase64(length) {
  const buf = crypto.randomBytes(length);
  return buf.toString("base64").substring(0, length);
}

module.exports = {
  __brancaDefaults,
  algorithms,
  isToken,
  generateKey,
  encrypt,
  decrypt
};
