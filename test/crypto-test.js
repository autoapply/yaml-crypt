const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const crypto = require('../lib/crypto');

require('./crypto-util').setupCrypto();

describe('crypto', () => {
    it('should return the encrypted content (fernet)', () => {
        const result = crypto.fernetEncrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H', 'Hello, world!');
        expect(result).to.equal('gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==');
    });

    it('should return the encrypted content (branca)', () => {
        const result = crypto.brancaEncrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H', 'Hello, world!');
        expect(result).to.equal('XUvrtHkyXTh1VUW885Ta4V5eQ3hBMFQMC3S3QwEfWzKWVDt3A5TnVUNtVXubi0fsAA8eerahpobwC8');
    });

    it('should return the decrypted content (fernet)', () => {
        const key = 'aehae5Ui0Eechaeghau9Yoh9jufiep7H';
        const encrypted = 'gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==';
        expect(crypto.fernetDecrypt(key, encrypted)).to.equal('Hello, world!');
    });

    it('should return the decrypted content (branca)', () => {
        const key = 'aehae5Ui0Eechaeghau9Yoh9jufiep7H';
        const encrypted = 'XUvrtHkyXTh1VUW885Ta4V5eQ3hBMFQMC3S3QwEfWzKWVDt3A5TnVUNtVXubi0fsAA8eerahpobwC8';
        expect(crypto.brancaDecrypt(key, encrypted)).to.equal('Hello, world!');
    });
});
