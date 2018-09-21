#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const process = require('process');
const childProcess = require('child_process');

const tmp = require('tmp');
const argparse = require('argparse');
const yaml = require('js-yaml');

const yamlcrypt = require('../lib/yaml-crypt');
const yamlcryptHelper = require('../lib/yaml-crypt-helper');

require('pkginfo')(module);

function main() {
    let cfg;
    try {
        cfg = config();
    } catch (e) {
        console.warn('could not read config file, using default!');
        if (e.message) {
            console.warn(`error: ${e.message}`);
        }
        cfg = {};
    }
    try {
        run(null, cfg, {});
    } catch (e) {
        if (e instanceof ExitError) {
            process.exit(e.status);
        } else if (e instanceof UsageError || e instanceof UnknownError) {
            console.error(`${module.exports.name}: error: ${e.message}`);
            process.exit(5);
        } else if (e instanceof ConfigurationError) {
            console.error(`${module.exports.name}: could not parse configuration: ${e.message}`);
            process.exit(6);
        } else {
            throw e;
        }
    }
}

function config() {
    const home = `${os.homedir()}/.yaml-crypt`;
    let raw = null;
    for (const filename of ['config.yaml', 'config.yml']) {
        try {
            raw = fs.readFileSync(`${home}/${filename}`);
            break;
        } catch (e) {
            if (e.code === 'ENOENT') {
                continue;
            } else {
                throw e;
            }
        }
    }
    if (raw) {
        return yaml.safeLoad(raw);
    } else {
        // default config
        return {};
    }
}

function run(argv, config = {}, options = {}) {
    class Parser extends argparse.ArgumentParser {
        exit(status, message) {
            if (message) {
                if (status === 0) {
                    this._printMessage(message);
                } else {
                    this._printMessage(message, process.stderr);
                }
            }
            throw new ExitError(status || 0);
        }

        error(err) {
            if (err instanceof ExitError) {
                throw err;
            } else {
                super.error(err);
            }
        }

        _printMessage(message, stream) {
            if (message) {
                if (options.stdout) {
                    stream = options.stdout;
                } else if (!stream) {
                    stream = process.stdout;
                }
                stream.write('' + message);
            }
        }
    }
    const parser = new Parser({
        prog: module.exports.name,
        version: module.exports.version,
        addHelp: true,
        description: module.exports.description
    });
    parser.addArgument(['--debug'], {
        action: 'storeTrue',
        help: 'Show debugging output'
    });
    parser.addArgument(['-e', '--encrypt'], {
        action: 'storeTrue',
        help: 'Encrypt data'
    });
    parser.addArgument(['-d', '--decrypt'], {
        action: 'storeTrue',
        help: 'Decrypt data'
    });
    parser.addArgument(['--generate-key'], {
        action: 'storeTrue',
        help: 'Generate a new random key. Use -a to specify the algorithm'
    });
    parser.addArgument(['-k'], {
        action: 'append',
        metavar: '<key>',
        help: 'Use the given key to decrypt data. Can be given multiple times. See section "Key sources" for details'
    });
    parser.addArgument(['-K'], {
        metavar: '<key>',
        help: 'Use the given key to encrypt data. See section "Key sources" for details'
    });
    parser.addArgument(['-a', '--algorithm'], {
        metavar: '<algorithm>',
        help: 'The encryption algorithm to use. Must be one of "fernet" (default) or "branca"'
    });
    parser.addArgument(['-E', '--edit'], {
        action: 'storeTrue',
        help: 'Open an editor for the given files, transparently decrypting and encrypting the file content'
    });
    parser.addArgument(['-B', '--base64'], {
        action: 'storeTrue',
        help: 'Encode values using Base64 encoding before encrypting and decode values after decrypting'
    });
    parser.addArgument(['--path'], {
        metavar: '<yaml-path>',
        help: 'Only process values below the given YAML path. For the document {obj:{key:secret},other:[value1,value2]} use "--path=obj.key" to only process "secret"'
    });
    parser.addArgument(['--raw'], {
        action: 'storeTrue',
        help: 'Encrypt/decrypt raw messages instead of YAML documents'
    });
    parser.addArgument(['-D', '--dir'], {
        action: 'storeTrue',
        help: 'Allows to pass directories as input, will process all files within the given directories (non-recursive)'
    });
    parser.addArgument(['--keep'], {
        action: 'storeTrue',
        help: 'Keep the original files after encryption/decryption'
    });
    parser.addArgument(['file'], {
        nargs: '*',
        metavar: '<file>',
        help: 'Input file(s) to process'
    });
    if (process.argv && process.argv.includes('--help')) {
        parser.addArgumentGroup({
            title: 'Configuration file',
            description: 'During startup, yaml-crypt will look for a configuration file '
                + '"config.yaml" or "config.yml" in the folder "$HOME/.yaml-crypt" and read keys from '
                + 'the array "keys". Each key is expected to be an object with the required '
                + 'attribute "key" which contains the raw key data and an optional attribute '
                + '"name" with a custom name for that key.'
        });
        parser.addArgumentGroup({
            title: 'Key sources',
            description: 'Keys can be provided from multiple sources: configuration file, environment variables, key files and file descriptors. '
                + 'When no explicit specifier is given, any arguments will be treated as key files. To select a specific source, '
                + 'specify "c:" or "config:" for configuration file, "e:" or "env:" for environment variables, "fd:" for file descriptors and "f:" for files. '
                + 'For example, "yaml-crypt -k c:my-key -k e:MY_KEY -k fd:0 -k f:my.key" will read the key named "my-key" from '
                + 'the configuration file, read a key from the environment variable "MY_KEY", read another key from file descriptor 0 (stdin) and another key from '
                + 'the local file "my.key".'
        });
        parser.addArgumentGroup({
            title: 'Decryption keys',
            description: 'When no keys are given, decryption keys are read from the configuration file. '
                + 'When no decryption keys are given, but an encryption key is given, that key will also be '
                + 'used for decryption. '
                + 'All provided decryption keys are tried, in order, until the data can be successfully decrypted. '
                + 'If none of the available keys matches, the operation fails.'
        });
        parser.addArgumentGroup({
            title: 'Encryption keys',
            description: 'When no encryption key is given and only one decryption key is available, that '
                + 'key will be used for encryption. When editing a file and no encryption key is given, '
                + 'the matching decryption key will be used to encrypt the modified data. '
                + 'In all other cases, an encryption key must be explicitly selected using "-K".'
        });
        parser.epilog = 'For more information, visit https://github.com/autoapply/yaml-crypt';
    } else {
        parser.epilog = 'For more details, specify --help';
    }
    const args = parser.parseArgs(argv);
    if (args.encrypt && args.decrypt) {
        throw new UsageError('cannot combine --encrypt and --decrypt!');
    }
    if (args.raw && args.path) {
        throw new UsageError('cannot combine --raw and --path!');
    }
    if (args.raw && args.file.length) {
        throw new UsageError('no files may be given when --raw is used!');
    }
    if (args.edit && args.path) {
        throw new UsageError('cannot combine --edit and --path!');
    }
    if (args.edit && args.raw) {
        throw new UsageError('cannot combine --edit and --raw!');
    }
    if (args.edit && args.keep) {
        throw new UsageError('cannot combine --edit and --keep!');
    }
    if (args.edit && args.encrypt) {
        throw new UsageError('cannot combine --edit and --encrypt!');
    }
    if (args.edit && args.decrypt) {
        throw new UsageError('cannot combine --edit and --decrypt!');
    }
    if (args.edit && !args.file.length) {
        throw new UsageError('option --edit used, but no files given!');
    }
    if (!args.generate_key && !args.k && (!config.keys || !config.keys.length)) {
        throw new UsageError('no keys given and no default keys configured!');
    }
    if (args.keep && !args.file.length) {
        throw new UsageError('option --keep used, but no files given!');
    }
    if (args.generate_key && args.encrypt) {
        throw new UsageError('cannot combine --generate-key and --encrypt!');
    }
    if (args.generate_key && args.decrypt) {
        throw new UsageError('cannot combine --generate-key and --decrypt!');
    }
    if (args.generate_key && args.file && args.file.length) {
        throw new UsageError('option --generate-key used, but files given!');
    }
    try {
        _run(args, config, options);
    } catch (e) {
        if (args.debug || e instanceof ConfigurationError) {
            throw e;
        } else {
            throw new UnknownError(e.message);
        }
    }
}

function _run(args, config, options) {
    let algorithm = null;
    for (const a of yamlcrypt.algorithms) {
        if (a === args.algorithm || a.startsWith(`${args.algorithm}:`)) {
            algorithm = a;
            break;
        }
    }
    if (args.algorithm && !algorithm) {
        throw new UsageError(`unknown encryption algorithm: ${args.algorithm}`);
    }
    let input;
    if (options.stdin) {
        input = options.stdin;
    } else {
        input = process.stdin;
    }
    let output;
    if (options.stdout) {
        output = options.stdout;
    } else {
        output = process.stdout;
        output.on('error', err => {
            if (err && err.code === 'EPIPE') {
                console.error('broken pipe');
            } else {
                console.error('unknown I/O error!');
            }
        });
    }
    const configKeys = readConfigKeys(config);
    const keys = [];
    if (args.k) {
        keys.push(...args.k.map(k => readKey(configKeys, k)));
    } else {
        configKeys.forEach(k => keys.push(k.key));
    }
    const encryptionKey = (args.K
        ? readKey(configKeys, args.K)
        : (keys.length === 1 ? keys[0] : null));
    if (args.generate_key) {
        const key = yamlcrypt.generateKey(algorithm);
        output.write(key);
        output.write('\n');
    } else if (args.edit) {
        for (const file of args.file) {
            editFile(file, keys, encryptionKey, algorithm, args, config);
        }
    } else if (args.file.length) {
        for (const file of args.file) {
            processFileArg(file, keys, encryptionKey, algorithm, args);
        }
    } else {
        let encrypt;
        if (args.encrypt) {
            encrypt = true;
        } else if (args.decrypt) {
            encrypt = false;
        } else {
            throw new UsageError('no input files, but no operation (--encrypt/--decrypt) given!');
        }
        if (encrypt) {
            checkEncryptionKey(keys, encryptionKey);
        }
        const opts = { 'base64': args.base64, 'algorithm': algorithm };
        readInput(input, buf => {
            if (args.raw) {
                if (encrypt) {
                    const crypt = yamlcrypt.encrypt(encryptionKey, opts);
                    output.write(crypt.encryptRaw(buf));
                    output.write('\n');
                } else {
                    const result = tryDecrypt(opts, keys, crypt => crypt.decryptRaw(buf));
                    output.write(result);
                }
            } else {
                let strs = [];
                if (encrypt) {
                    const crypt = yamlcrypt.encrypt(encryptionKey, opts);
                    yaml.safeLoadAll(buf, obj => {
                        yamlcryptHelper.processStrings(obj, args.path, str => new yamlcrypt.Plaintext(str));
                        const encrypted = crypt.safeDump(obj);
                        strs.push(encrypted);
                    });
                } else {
                    strs = tryDecrypt(opts, keys, crypt => {
                        const result = [];
                        crypt.safeLoadAll(buf, obj => result.push(yaml.safeDump(obj)));
                        return result;
                    });
                }
                for (let idx = 0; idx < strs.length; idx++) {
                    if (idx > 0) {
                        output.write('---\n');
                    }
                    output.write(strs[idx]);
                }
            }
        });
    }
}

function readInput(input, callback) {
    if (typeof input === 'string' || input instanceof String || Buffer.isBuffer(input)) {
        callback(input);
    } else {
        const ret = [];
        let len = 0;
        input.on('readable', () => {
            let chunk;
            while ((chunk = input.read())) {
                ret.push(chunk);
                len += chunk.length;
            }
        });
        input.on('end', () => {
            callback(Buffer.concat(ret, len));
        });
    }
}

function checkEncryptionKey(keys, encryptionKey) {
    if (!encryptionKey) {
        if (keys.length) {
            throw new UsageError('encrypting, but multiple keys given! '
                + 'Use -K to explicitly specify an encryption key.');
        } else {
            throw new UsageError('encrypting, but no keys given!');
        }
    }
}

function readConfigKeys(config) {
    const keys = [];
    if (Array.isArray(config.keys)) {
        for (const obj of config.keys) {
            if (obj.key) {
                let key;
                const type = typeof (obj.key);
                if (type === 'string') {
                    key = obj.key.trim();
                } else if (Buffer.isBuffer(obj.key)) {
                    key = obj.key.toString('utf8').trim();
                } else {
                    throw new ConfigurationError(`key entry is not a string: ${type}`);
                }
                const name = obj.name || '';
                keys.push({ key, name });
            } else {
                throw new ConfigurationError('attribute key missing for key entry!');
            }
        }
    }
    for (let i = 0; i < keys.length; i++) {
        for (let j = 0; j < keys.length; j++) {
            if (i !== j) {
                if (keys[i].name && keys[i].name === keys[j].name) {
                    throw new ConfigurationError(`non-unique key name: ${keys[i].name}`);
                }
            }
        }
    }
    return keys;
}

function readKey(configKeys, key) {
    let prefix;
    let arg;
    if (key.includes(':')) {
        const idx = key.indexOf(':');
        prefix = key.substring(0, idx);
        arg = key.substring(idx + 1);
    } else {
        prefix = 'f';
        arg = key;
    }
    if (prefix === 'c' || prefix === 'config') {
        for (const k of configKeys) {
            if (k.name === arg) {
                return k.key;
            }
        }
        throw new UsageError(`key not found in configuration file: ${arg}`);
    } else if (prefix === 'e' || prefix === 'env') {
        const str = process.env[arg];
        if (!str || !str.trim()) {
            throw new UsageError(`no such environment variable: ${arg}`);
        }
        return str.trim();
    } else if (prefix === 'fd') {
        const fd = parseInt(arg);
        if (fd || fd === 0) {
            return readFd(fd).trim();
        } else {
            throw new UsageError(`not a file descriptor: ${arg}`);
        }
    } else if (prefix === 'f' || prefix === 'file') {
        let raw;
        try {
            raw = fs.readFileSync(arg);
        } catch (e) {
            if (e.code === 'ENOENT') {
                throw new UsageError(`key file does not exist: ${arg}`);
            } else {
                throw e;
            }
        }
        return raw.toString('utf8').trim();
    } else {
        throw new UsageError(`unknown key argument: ${key}`);
    }
}

function readFd(fd) {
    var buf = Buffer.alloc(1024);
    let str = '';
    while (true) {
        var len = fs.readSync(fd, buf, 0, buf.length);
        if (!len) {
            break;
        }
        str += buf.toString('utf8', 0, len);
    }
    return str;
}

function plaintextFile(file) {
    return file.endsWith('.yaml') || file.endsWith('.yml');
}

function encryptedFile(file) {
    return file.endsWith('.yaml-crypt') || file.endsWith('.yml-crypt');
}

function processFileArg(file, keys, encryptionKey, algorithm, args) {
    const stat = fs.statSync(file);
    if (stat.isDirectory()) {
        if (args.dir) {
            fs.readdirSync(file)
                .filter(f => {
                    if (args.encrypt) {
                        return plaintextFile(f);
                    } else if (args.decrypt) {
                        return encryptedFile(f);
                    } else {
                        return plaintextFile(f) || encryptedFile(f);
                    }
                })
                .forEach(f => processFile(file + '/' + f, keys, encryptionKey, algorithm, args));
        } else {
            throw new UsageError(`directories will be skipped unless --dir given: ${file}`);
        }
    } else {
        processFile(file, keys, encryptionKey, algorithm, args);
    }
}

function processFile(file, keys, encryptionKey, algorithm, args) {
    let encrypt;
    if (plaintextFile(file)) {
        encrypt = true;
    } else if (encryptedFile(file)) {
        encrypt = false;
    } else {
        throw new UsageError(`unknown file extension: ${file}`);
    }
    if (encrypt && args.decrypt) {
        throw new UsageError(`decrypted file, but --decrypt given: ${file}`);
    } else if (!encrypt && args.encrypt) {
        throw new UsageError(`encrypted file, but --encrypt given: ${file}`);
    }
    if (encrypt) {
        checkEncryptionKey(keys, encryptionKey);
    }
    let content;
    try {
        content = fs.readFileSync(file);
    } catch (e) {
        if (e.code === 'ENOENT') {
            throw new UsageError(`file does not exist: ${file}`);
        } else {
            throw e;
        }
    }
    const output = (encrypt ? file + '-crypt' : file.substring(0, file.length - '-crypt'.length));
    if (fs.existsSync(output)) {
        throw new UsageError(`output file already exists: ${output}`);
    }
    let strs = [];
    const opts = { 'base64': args.base64, 'algorithm': algorithm };
    if (encrypt) {
        const crypt = yamlcrypt.encrypt(encryptionKey, opts);
        yaml.safeLoadAll(content, obj => {
            yamlcryptHelper.processStrings(obj, args.path, str => new yamlcrypt.Plaintext(str));
            const encrypted = crypt.safeDump(obj);
            strs.push(encrypted);
        });
    } else {
        strs = tryDecrypt(opts, keys, crypt => {
            const result = [];
            crypt.safeLoadAll(content, obj => result.push(yaml.safeDump(obj)));
            return result;
        });
    }
    if (!args.keep) {
        fs.renameSync(file, output);
    }
    writeYaml(strs, output);
}

function tryDecrypt(opts, keys, callback) {
    let result = null;
    let success = false;
    for (const key of keys) {
        try {
            const crypt = yamlcrypt.decrypt(key, opts);
            result = callback(crypt);
            success = true;
            break;
        } catch (e) {
            continue;
        }
    }
    if (success) {
        return result;
    } else {
        throw new Error('no matching key to decrypt the given data!');
    }
}

function editFile(file, keys, encryptionKey, algorithm, args, config) {
    if (!encryptedFile(file)) {
        throw new UsageError(`unexpected extension, expecting .yaml-crypt or .yml-crypt: ${file}`);
    }

    let content;
    try {
        content = fs.readFileSync(file);
    } catch (e) {
        if (e.code === 'ENOENT') {
            throw new UsageError(`file does not exist: ${file}`);
        } else {
            throw e;
        }
    }

    const dir = path.dirname(path.resolve(file));

    const editor = config['editor'] || process.env['EDITOR'] || 'vim';

    const tmpFile = tmp.fileSync({ 'dir': dir, 'postfix': '.yaml', 'keep': true });
    try {
        const opts = { 'base64': args.base64, 'algorithm': algorithm };
        const transformed = yamlcryptHelper.transform(content, keys, encryptionKey, opts, str => {
            fs.writeSync(tmpFile.fd, str);
            fs.closeSync(tmpFile.fd);

            childProcess.spawnSync(editor, [tmpFile.name], { 'stdio': 'inherit' });

            return fs.readFileSync(tmpFile.name);
        });
        fs.writeFileSync(tmpFile.name, transformed);
        fs.renameSync(tmpFile.name, file);
    } finally {
        if (fs.existsSync(tmpFile.name)) {
            fs.unlinkSync(tmpFile.name);
        }
    }
}

function writeYaml(strs, file) {
    const fd = fs.openSync(file, 'w');
    try {
        for (let idx = 0; idx < strs.length; idx++) {
            if (idx > 0) {
                fs.writeSync(fd, '---\n');
            }
            fs.writeSync(fd, strs[idx]);
        }
    } finally {
        fs.closeSync(fd);
    }
}

class UsageError extends Error { }

class UnknownError extends Error { }

class ConfigurationError extends Error { }

class ExitError extends Error {
    constructor(status) {
        super(`Exit: ${status}`);
        this.status = status;
    }
}

module.exports.run = run;

if (require.main === module) {
    main();
}
