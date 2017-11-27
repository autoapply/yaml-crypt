const fs = require('fs');

const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const yamlcrypt = require('../lib/yaml-crypt');

require('./crypto-util').setupFernet();

describe('yaml-crypt', () => {
    it('should read the decrypted content', () => {
        const yaml = yamlcrypt.decrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        const content = fs.readFileSync('./test/test-1.yaml-crypt');
        const result = yaml.safeLoad(content);
        expect(result.key1.toString()).to.equal('Hello, world!');
    });

    it('should return the encrypted content', () => {
        const yaml = yamlcrypt.encrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        const result = yaml.safeDump({ 'key1': new yamlcrypt.Plaintext('Hello, world!') });
        const expected = fs.readFileSync('./test/test-1.yaml-crypt').toString('utf8');
        expect(result).to.equal(expected);
    });

    it('should return the base64 encrypted content', () => {
        const yaml = yamlcrypt.encrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H', { 'base64': true });
        const result = yaml.safeDump({ 'base64': new yamlcrypt.Plaintext('Hello, world!') });
        const expected = fs.readFileSync('./test/test-4.yaml-crypt').toString('utf8');
        expect(result).to.equal(expected);
    });

    it('should read the decrypted base64 content', () => {
        const yaml = yamlcrypt.decrypt('aehae5Ui0Eechaeghau9Yoh9jufiep7H', { 'base64': true });
        const content = fs.readFileSync('./test/test-4.yaml-crypt');
        const result = yaml.safeLoad(content);
        expect(result.base64.toString()).to.equal('Hello, world!');
    });
});
