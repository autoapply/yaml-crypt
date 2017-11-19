const fs = require('fs');
const stream = require('stream');

const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const tmp = require('tmp');
const yaml = require('js-yaml');

const yamlcryptcli = require('../bin/yaml-crypt-cli');

require('./crypto-util').setupFernet();

describe('yaml-crypt-cli', () => it('run() should throw an error when using --path and --raw', () => {
    const out = new stream.Writable();
    expect(() => yamlcryptcli.run(['--path', 'x', '--raw'], {}, { 'stdout': out })).to.throw();
}));

describe('yaml-crypt-cli', () => it('run() should encrypt the given YAML file', () => {
    const keyFile = tmp.fileSync();
    fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');
    const input = tmp.fileSync({ 'postfix': '.yaml' });
    fs.writeSync(input.fd, yaml.safeDump({ 'first': 'Hello, world!', 'second': 'Hello!' }));
    const out = new stream.Writable();
    yamlcryptcli.run(['-k', keyFile.name, input.name], {}, { 'stdout': out });
    const output = fs.readFileSync(input.name + '-crypt');
    const expected = fs.readFileSync('./test/test-2.yaml-crypt');
    expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
}));
