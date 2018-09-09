const fs = require('fs');

const mocha = require('mocha');
const describe = mocha.describe;
const it = mocha.it;
const chai = require('chai');
const expect = chai.expect;

const tmp = require('tmp');
const yaml = require('js-yaml');

const yamlcryptcli = require('../bin/yaml-crypt-cli');

require('./crypto-util').setupCrypto();

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
    it('should throw an error when using --unknown-option', () => {
        expect(() => yamlcryptcli.run(['--unknown-option'], {}, { 'stdout': new Out() }))
            .to.throw().with.property('status', 2);
    });

    it('should display usage info when using --help', () => {
        expect(() => yamlcryptcli.run(['--help'], {}, { 'stdout': new Out() }))
            .to.throw().with.property('status', 0);
    });

    it('should throw an error when using --path and --raw', () => {
        expect(() => runWithKeyFile(['--path', 'x', '--raw'], {}, { 'stdout': new Out() }))
            .to.throw(/cannot combine/);
    });

    it('should throw an error when passing directory without --dir', () => {
        expect(() => runWithKeyFile(['.'], {}, { 'stdout': new Out() }))
            .to.throw(/directories will be skipped/);
    });

    it('should throw an error when passing non-existing files to --edit', () => {
        expect(() => runWithKeyFile(['--edit', 'x.yaml-crypt'], {}, { 'stdout': new Out() }))
            .to.throw(/file does not exist/);
    });

    it('should throw an error when encrypting with two keys', () => {
        const secondKeyFile = tmp.fileSync();
        fs.writeSync(secondKeyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep72');
        expect(() => runWithKeyFile(['-k', secondKeyFile.name, '-e'], {}, { 'stdout': new Out() }))
            .to.throw(/encrypting, but multiple keys given/);
    });

    it('should throw an error when trying to read a nonexisting environment variable', () => {
        expect(() => yamlcryptcli.run(['-k', 'env:YAML_CRYPT_321'], {}, { 'stdout': new Out() }))
            .to.throw(/no such environment variable/);
    });

    it('should throw an error when passing an invalid file descriptor', () => {
        expect(() => yamlcryptcli.run(['-k', 'fd:x'], {}, { 'stdout': new Out() }))
            .to.throw(/not a file descriptor/);
    });

    it('should generate a key', () => {
        const options = {
            'stdin': '',
            'stdout': new Out()
        };
        yamlcryptcli.run(['--debug', '--generate-key'], {}, options);
        expect(options.stdout.str.trimRight()).to.have.lengthOf(32);
    });

    it('should encrypt the given YAML file (fernet)', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.copyFileSync('./test/test-2.yaml', input.name);
        runWithKeyFile([input.name], {}, { 'stdout': new Out() });
        const output = fs.readFileSync(input.name + '-crypt');
        const expected = fs.readFileSync('./test/test-2a.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should encrypt the given YAML file (branca)', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.copyFileSync('./test/test-2.yaml', input.name);
        runWithKeyFile(['-a', 'branca', input.name], {}, { 'stdout': new Out() });
        const output = fs.readFileSync(input.name + '-crypt');
        const expected = fs.readFileSync('./test/test-2b.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should decrypt the given YAML file', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml-crypt' });
        fs.copyFileSync('./test/test-2a.yaml-crypt', input.name);
        runWithKeyFile([input.name], {}, { 'stdout': new Out() });
        const output = fs.readFileSync(input.name.substring(0, input.name.length - '-crypt'.length));
        const expected = fs.readFileSync('./test/test-2.yaml');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should encrypt only parts of the YAML file when using --path', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.writeSync(input.fd, yaml.safeDump({ 'a': { 'b': { 'c': 'secret' } }, 'x': 'plain' }));
        runWithKeyFile(['--path', 'a.b.c', input.name], {}, { 'stdout': new Out() });
        const output = fs.readFileSync(input.name + '-crypt');
        const expected = fs.readFileSync('./test/test-3.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });

    it('should remove the old files', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.copyFileSync('./test/test-2.yaml', input.name);
        runWithKeyFile([input.name], {}, { 'stdout': new Out() });
        expect(fs.existsSync(input.name)).to.equal(false);
    });

    it('should not remove the old files when using --keep', () => {
        const input = tmp.fileSync({ 'postfix': '.yaml' });
        fs.copyFileSync('./test/test-2.yaml', input.name);
        runWithKeyFile(['--keep', input.name], {}, { 'stdout': new Out() });
        expect(fs.existsSync(input.name)).to.equal(true);
    });

    function runWithKeyFile(argv, config, options) {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');
        return yamlcryptcli.run(['--debug', '-k', keyFile.name].concat(argv), config, options);
    }

    it('should throw an error when no matching key is available', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'INVALID_KEYchaeghau9Yoh9jufiep7H');
        const input = tmp.fileSync({ 'postfix': '.yaml-crypt' });
        fs.copyFileSync('./test/test-2a.yaml-crypt', input.name);
        expect(() => yamlcryptcli.run(['-k', keyFile.name, input.name], {}, { 'stdout': new Out() }))
            .to.throw(/no matching key/);
    });

    it('should throw an error when no named key is available in the config file', () => {
        const config = {
            'keys': []
        };
        const options = {
            'stdin': '',
            'stdout': new Out()
        };
        expect(() => yamlcryptcli.run(['-k', 'config:name1', '-d'], config, options))
            .to.throw(/key not found in configuration file/);
    });

    it('should throw an error when the key names are not unique in the config file', () => {
        const config = {
            'keys': [
                { 'key': 'a', 'name': 'key1' },
                { 'key': 'b', 'name': 'key1' }
            ]
        };
        const options = {
            'stdin': '',
            'stdout': new Out()
        };
        expect(() => yamlcryptcli.run(['-d'], config, options))
            .to.throw(/non-unique key name/);
    });

    it('should decrypt the given input', () => {
        const config = {
            'keys': [
                { 'key': 'INVALID_KEY____________________X' },
                { 'key': 'aehae5Ui0Eechaeghau9Yoh9jufiep7H' }
            ]
        };
        const options = {
            'stdin': fs.readFileSync('./test/test-2a.yaml-crypt'),
            'stdout': new Out()
        };
        yamlcryptcli.run(['-d'], config, options);
        const expected = fs.readFileSync('./test/test-2.yaml').toString();
        expect(options.stdout.str).to.equal(expected);
    });

    it('should decrypt the given input when using --raw', () => {
        const config = {
            'keys': [
                { 'key': 'INVALID_KEY_123________________X' },
                { 'key': 'aehae5Ui0Eechaeghau9Yoh9jufiep7H' },
                { 'key': 'INVALID_KEY_345________________X' }
            ]
        };
        const input = 'gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==';
        const options = {
            'stdin': input,
            'stdout': new Out()
        };
        yamlcryptcli.run(['-d', '--raw'], config, options);
        expect(options.stdout.str).to.equal('Hello, world!');
    });

    it('should encrypt the whole input when using --raw', () => {
        const config = {
            'keys': [
                { 'key': 'KEY_THAT_SHOULD_NOT_BE_USED_____', 'name': 'key1' },
                { 'key': 'aehae5Ui0Eechaeghau9Yoh9jufiep7H', 'name': 'key2' }
            ]
        };
        const options = {
            'stdin': 'Hello, world!',
            'stdout': new Out()
        };
        yamlcryptcli.run(['-e', '--raw', '-K', 'c:key2'], config, options);
        const expected = 'gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==\n';
        expect(options.stdout.str).to.equal(expected);
    });

    it('should return the same YAML file when using --edit and not changing anything', () => {
        const keyFile = tmp.fileSync();
        fs.writeSync(keyFile.fd, 'aehae5Ui0Eechaeghau9Yoh9jufiep7H');

        const input = tmp.fileSync({ 'postfix': '.yaml-crypt' });
        fs.copyFileSync('./test/test-2a.yaml-crypt', input.name);

        yamlcryptcli.run(['--debug', '-k', keyFile.name, '--edit', input.name], { 'editor': 'touch' }, {});

        const output = fs.readFileSync(input.name);
        const expected = fs.readFileSync('./test/test-2a.yaml-crypt');
        expect(output.toString('utf8')).to.equal(expected.toString('utf8'));
    });
});
