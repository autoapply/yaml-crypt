#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const process = require('process');

const argparse = require('argparse');
const yaml = require('js-yaml');

const yamlcrypt = require('../lib/yaml-crypt');

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
        help: 'Key files to use. Can be given multiple times to automatically select a matching decryption key'
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
    if (!args.key && !config.defaultKeyFile) {
        throw new UsageError('no key file given and no default key file configured!');
    }
    if (args.rm && !args.file.length) {
        throw new UsageError('option --rm used, but no files given!');
    }
    try {
        _run(args, config, options);
    } catch (e) {
        if (args.debug) {
            throw e;
        } else {
            throw new UnknownError(e.message);
        }
    }
}

function _run(args, config, options) {
    const keys = [];
    if (args.key) {
        keys.push(...args.key.map(key => readKey(key)));
    } else if (config.defaultKeyFile) {
        keys.push(readKey(config.defaultKeyFile));
    }
    if (args.file.length) {
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
        let encode;
        if (args.base64) {
            if (encrypt) {
                encode = str => new Buffer(str).toString('base64');
            } else {
                encode = str => new Buffer(str, 'base64').toString();
            }
        } else {
            encode = str => str;
        }
        let input;
        if (options.stdin) {
            input = options.stdin;
        } else {
            input = readStdin();
        }
        let output;
        if (options.stdout) {
            output = options.stdout;
        } else {
            output = process.stdout;
        }
        if (args.raw) {
            if (encrypt) {
                const crypt = yamlcrypt.encrypt(keys[0]);
                output.write(crypt.encryptRaw(encode(input)));
                output.write('\n');
            } else {
                const crypt = yamlcrypt.decrypt(keys[0]);
                let result = crypt.decryptRaw(input);
                output.write(encode(result));
            }
        } else {
            const strs = [];
            if (encrypt) {
                const crypt = yamlcrypt.encrypt(keys[0]);
                yaml.safeLoadAll(input, obj => {
                    processStrings(obj, args.path, str => yamlcrypt.plaintext(str));
                    const encrypted = crypt.safeDump(obj);
                    strs.push(encrypted);
                });
            } else {
                const crypt = yamlcrypt.decrypt(keys);
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

function readStdin() {
    var buf = Buffer.alloc(1024);
    let str = '';
    while (true) {
        var len = fs.readSync(process.stdin.fd, buf, 0, buf.length);
        if (!len) {
            break;
        }
        str += buf.toString(null, 0, len);
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
        const crypt = yamlcrypt.encrypt(keys[0]);
        yaml.safeLoadAll(content, obj => {
            processStrings(obj, args.path, str => yamlcrypt.plaintext(str));
            const encrypted = crypt.safeDump(obj);
            strs.push(encrypted);
        });
    } else {
        let success = false;
        for (const key of keys) {
            try {
                strs = [];
                const crypt = yamlcrypt.decrypt(key);
                crypt.safeLoadAll(content, obj => strs.push(yaml.safeDump(obj)));
                success = true;
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

function processStrings(obj, path, callback) {
    let subobj = obj;
    if (path) {
        const parts = path.split('.');
        for (let idx = 0; idx < parts.length; idx++) {
            const part = parts[idx];
            if (idx === parts.length - 1 && typeof subobj[part] === 'string') {
                subobj[part] = callback(subobj[part]);
                return;
            } else {
                subobj = subobj[part];
            }
        }
    }
    for (const key in subobj) {
        if (subobj.hasOwnProperty(key)) {
            const value = subobj[key];
            if (typeof value === 'string') {
                subobj[key] = callback(value);
            } else if (typeof value === 'object') {
                processStrings(value, null, callback);
            }
        }
    }
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
