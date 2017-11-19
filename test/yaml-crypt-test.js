const fs = require('fs');

const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const yamlcrypt = require('../lib/yaml-crypt');

require('./crypto-util').setupFernet();

describe('yaml-crypt', () => it('decrypt() should read the decrypted content', () => {
    const yaml = yamlcrypt.decrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H');
    const content = fs.readFileSync('./test/test-1.yaml-crypt');
    const result = yaml.safeLoad(content);
    expect(result.key1.toString()).to.equal('Hello, world!');
}));

describe('yaml-crypt', () => it('encrypt() should return the encrypted content', () => {
    const yaml = yamlcrypt.encrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H');
    const result = yaml.safeDump({ 'key1': new yamlcrypt.PlaintextFernet('Hello, world!') });
    const expected = fs.readFileSync('./test/test-1.yaml-crypt').toString('utf8');
    expect(result).to.equal(expected);
}));
