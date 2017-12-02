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
    parser.addArgument(['-k', '--key'], {
        action: 'append',
        metavar: '<key-file>',
        help: 'Read a key from the given file path. Can be given multiple times to automatically select a matching decryption key'
    });
    parser.addArgument(['--key-fd'], {
        action: 'append',
        metavar: '<key-fd>',
        help: 'Read a key from the given file descriptor. Can be given multiple times'
    });
    parser.addArgument(['-E', '--edit'], {
        action: 'storeTrue',
        help: 'Open an editor for the given files, transparently decrypting and encrypting the file content'
    });
    parser.addArgument(['-B', '--base64'], {
        action: 'storeTrue',
        help: 'Encode/decode values using Base64 encoding before processing'
    });
    parser.addArgument(['--path'], {
        metavar: '<yaml-path>',
        help: 'Only process values below the given YAML path. For the document {obj:{key:secret},other:[value1,value2]} use "obj.key" to only process "secret"'
    });
    parser.addArgument(['--raw'], {
        action: 'storeTrue',
        help: 'Encrypt/decrypt raw messages from stdin instead of YAML documents'
    });
    parser.addArgument(['-D', '--dir'], {
        action: 'storeTrue',
        help: 'Allows to pass directories as input, will process all files within the given directories (non-recursive)'
    });
    parser.addArgument(['--rm'], {
        action: 'storeTrue',
        help: 'Delete original files after encryption/decryption. Use with caution!'
    });
    parser.addArgument(['file'], {
        nargs: '*',
        metavar: '<file>',
        help: 'Input files to process'
    });
    const args = parser.parseArgs(argv);
    if (args.encrypt && args.decrypt) {
        throw new UsageError('cannot combine --encrypt and --decrypt!');
    }
    if (args.raw && args.path) {
        throw new UsageError('options --raw and --path cannot be combined!');
    }
    if (args.raw && args.file.length) {
        throw new UsageError('no files may be given when --raw is used!');
    }
    if (args.edit && args.path) {
        throw new UsageError('options --edit and --path cannot be combined!');
    }
    if (args.edit && args.raw) {
        throw new UsageError('options --edit and --raw cannot be combined!');
    }
    if (args.edit && !args.file.length) {
        throw new UsageError('option --edit used, but no files given!');
    }
    if (!args.key && !args.key_fd && (!config.keys || !config.keys.length)) {
        throw new UsageError('no keys given and no default keys configured!');
    }
    if (args.rm && !args.file.length) {
        throw new UsageError('option --rm used, but no files given!');
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
    const keys = [];
    if (args.key || args.key_fd) {
        if (args.key) {
            keys.push(...args.key.map(key => readKey(key)));
        }
        if (args.key_fd) {
            for (const key of args.key_fd) {
                const fd = parseInt(key);
                if (fd || fd === 0) {
                    const str = readFd(fd);
                    keys.push(str.trim());
                } else {
                    throw new UsageError(`not a file descriptor: ${key}`);
                }
            }
        }
    } else if (config.keys) {
        for (const obj of config.keys) {
            if (obj.file && obj.key) {
                throw new ConfigurationError('either file or key must be set, not both!');
            } else if (obj.file) {
                keys.push(readKey(obj.file));
            } else if (obj.key) {
                const type = typeof (obj.key);
                if (type === 'string') {
                    keys.push(obj.key.trim());
                } else if (Buffer.isBuffer(obj.key)) {
                    keys.push(obj.key.toString('utf8').trim());
                } else {
                    throw new ConfigurationError(`key entry is not a string: ${type}`);
                }
            } else {
                throw new ConfigurationError('neither file nor key given for key entry!');
            }
        }
    }
    if (args.edit) {
        for (const file of args.file) {
            editFile(file, keys, args, config);
        }
    } else if (args.file.length) {
        for (const file of args.file) {
            processFileArg(file, keys, args);
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
        let input;
        if (options.stdin) {
            input = options.stdin;
        } else {
            input = readFd(process.stdin.fd);
        }
        let output;
        if (options.stdout) {
            output = options.stdout;
        } else {
            output = process.stdout;
        }
        if (args.raw) {
            if (encrypt) {
                const crypt = yamlcrypt.encrypt(keys[0], { 'base64': args.base64 });
                output.write(crypt.encryptRaw(input));
                output.write('\n');
            } else {
                const crypt = yamlcrypt.decrypt(keys[0], { 'base64': args.base64 });
                let result = crypt.decryptRaw(input);
                output.write(result);
            }
        } else {
            const strs = [];
            if (encrypt) {
                const crypt = yamlcrypt.encrypt(keys[0], { 'base64': args.base64 });
                yaml.safeLoadAll(input, obj => {
                    yamlcryptHelper.processStrings(obj, args.path, str => new yamlcrypt.Plaintext(str));
                    const encrypted = crypt.safeDump(obj);
                    strs.push(encrypted);
                });
            } else {
                const crypt = yamlcrypt.decrypt(keys[0], { 'base64': args.base64 });
                crypt.safeLoadAll(input, obj => strs.push(yaml.safeDump(obj)));
            }
            for (let idx = 0; idx < strs.length; idx++) {
                if (idx > 0) {
                    output.write('---\n');
                }
                output.write(strs[idx]);
            }
        }
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

function readKey(keyFile) {
    let raw;
    try {
        raw = fs.readFileSync(keyFile);
    } catch (e) {
        if (e.code === 'ENOENT') {
            throw new UsageError(`key file does not exist: ${keyFile}`);
        } else {
            throw e;
        }
    }
    return raw.toString('utf8').trim();
}

function plaintextFile(file) {
    return file.endsWith('.yaml') || file.endsWith('.yml');
}

function encryptedFile(file) {
    return file.endsWith('.yaml-crypt') || file.endsWith('.yml-crypt');
}

function processFileArg(file, keys, args) {
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
                .forEach(f => processFile(file + '/' + f, keys, args));
        } else {
            throw new UsageError(`directories will be skipped unless --dir given: ${file}`);
        }
    } else {
        processFile(file, keys, args);
    }
}

function processFile(file, keys, args) {
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
    if (encrypt && keys.length != 1) {
        throw new UsageError(`encrypting file, but more than one key given!`);
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
    if (encrypt) {
        if (keys.length > 1) {
            console.warn('warning: multiple keys given, using first key for encryption!');
        }
        const crypt = yamlcrypt.encrypt(keys[0], { 'base64': args.base64 });
        yaml.safeLoadAll(content, obj => {
            yamlcryptHelper.processStrings(obj, args.path, str => new yamlcrypt.Plaintext(str));
            const encrypted = crypt.safeDump(obj);
            strs.push(encrypted);
        });
    } else {
        let success = false;
        for (const key of keys) {
            try {
                strs = [];
                const crypt = yamlcrypt.decrypt(key, { 'base64': args.base64 });
                crypt.safeLoadAll(content, obj => strs.push(yaml.safeDump(obj)));
                success = true;
                break;
            } catch (e) {
                continue;
            }
        }
        if (!success) {
            throw new Error('No matching key to decrypt the given data!');
        }
    }
    writeYaml(strs, output);
    if (args.rm) {
        fs.unlinkSync(file);
    }
}

function editFile(file, keys, args, config) {
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

    const opts = { 'base64': args.base64 };
    const transformed = yamlcryptHelper.transform(content, keys, opts, str => {
        const tmpFile = tmp.fileSync({ 'dir': dir, 'postfix': '.yaml' });
        fs.writeSync(tmpFile.fd, str);
        fs.closeSync(tmpFile.fd);

        childProcess.spawnSync(editor, [tmpFile.name], { 'stdio': 'inherit' });

        return fs.readFileSync(tmpFile.name);
    });

    fs.writeFileSync(file, transformed);
}

function writeYaml(strs, file) {
    const fd = fs.openSync(file, 'wx');
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
