const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const crypto = require('../lib/crypto');

require('./crypto-util').setupFernet();

describe('crypto', () => it('fernetEncrypt() should return the encrypted content', () => {
    const result = crypto.fernetEncrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H', 'Hello, world!');
    expect(result).to.equal('gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==');
}));

describe('crypto', () => it('fernetDecrypt() should return the decrypted content', () => {
    const key = 'aehae5Ui0Eechaeghau9Yoh9jufiep7H';
    const encrypted = 'gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==';
    expect(crypto.fernetDecrypt(key, encrypted)).to.equal('Hello, world!');
}));
