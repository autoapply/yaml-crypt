const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const utils = require('../lib/utils');

describe('utils', () => {
    it('should throw an error when no key is given', () => {
        expect(() => utils.tryDecrypt()).to.throw(/no decryption keys given/);
    });
});
