const crypto = require('../lib/crypto');

const fernet = require('fernet');

/**
 * Ensures the crypto calls are reproducible
 */
function setupCrypto() {
    // Fernet:
    const setIV = fernet.Token.prototype.setIV;
    fernet.Token.prototype.setIV = function () {
        const iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        setIV.apply(this, [iv]);
    };
    const setTime = fernet.Token.prototype.setTime;
    fernet.Token.prototype.setTime = function () {
        setTime.apply(this, [1000]);
    };

    // Branca:
    crypto.brancaDefaults.ts = 1;
    crypto.brancaDefaults.nonce = Buffer.alloc(24, 1);
}

module.exports.setupCrypto = setupCrypto;
