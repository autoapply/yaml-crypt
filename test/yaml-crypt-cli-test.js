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

class Out {
    constructor() {
        this.str = '';
    }

    write(obj) {
        if (typeof obj === 'string') {
            this.str += obj;
        } else {
            this.str += obj.toString();
        }
    }
}

describe('yaml-crypt-cli', () => {
    it('should throw an error when using --path and --raw', () => {
        const out = new stream.Writable();
        expect(() => yamlcryptcli.run(['--path', 'x', '--raw'], {}, { 'stdout': out })).to.throw();
    });

    it('should throw an error when passing directory without --dir', () => {
        const out = new stream.Writable();
        expect(() => yamlcryptcli.run(['.'], {}, { 'stdout': out })).to.throw();
    });

    it('should encrypt the given YAML file', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.writeSync(input.fd, yaml.safeDump({ 'first': 'Hello, world!', 'second': 'Hello!' }));
        const out = new stream.Writable();
        yamlcryptcli.run(['-k', keyFile.name, input.name], {}, { 'stdout': out });
        const output = fs.readFileSync(input.name + '-crypt');
        const expected = fs.readFileSync('./test/test-2.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should encrypt only parts of the YAML file when using --path', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.writeSync(input.fd, yaml.safeDump({ 'a': { 'b': { 'c': 'secret' } }, 'x': 'plain' }));
        const out = new stream.Writable();
        yamlcryptcli.run(['-k', keyFile.name, '--path', 'a.b.c', input.name], {}, { 'stdout': out });
        const output = fs.readFileSync(input.name + '-crypt');
        const expected = fs.readFileSync('./test/test-3.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should decrypt the given input', () => {
        const config = {
            'keys': [
                { 'key': 'aehae5Ui0Eechaeghau9Yoh9jufiep7H' }
            ]
        };
        const options = {
            'stdin': fs.readFileSync('./test/test-2.yaml-crypt'),
            'stdout': new Out()
        };
        yamlcryptcli.run(['-d'], config, options);
        const expected = fs.readFileSync('./test/test-2.yaml').toString();
        expect(options.stdout.str).to.equal(expected);
    });

    it('should encrypt the whole input when using --raw', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        const config = {
            'keys': [
                { 'file': keyFile.name }
            ]
        };
        const options = {
            'stdin': 'Hello, world!',
            'stdout': new Out()
        };
        yamlcryptcli.run(['-e', '--raw'], config, options);
        const expected = 'gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==\n';
        expect(options.stdout.str).to.equal(expected);
    });

    it('should return the same YAML file when using --edit and not changing anything', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');

        const input = tmp.fileSync({ 'postfix': '.yaml-crypt' });
        fs.copyFileSync('./test/test-2.yaml-crypt', input.name);

        yamlcryptcli.run(['-k', keyFile.name, '--edit', input.name], { 'editor': 'touch' }, {});

        const output = fs.readFileSync(input.name);
        const expected = fs.readFileSync('./test/test-2.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });
});
