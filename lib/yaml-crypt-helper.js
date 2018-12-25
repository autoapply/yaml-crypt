const yaml = require('js-yaml');

const yamlcrypt = require('./yaml-crypt');

function safeDumpAll(objs, opts) {
    let str = '';
    for (let idx = 0; idx < objs.length; idx++) {
        if (idx > 0) {
            str += '---\n';
        }
        str += yaml.safeDump(objs[idx], opts);
    }
    return str;
}

function transform(content, keys, encryptionKey, opts, callback) {
    let key = null;
    let objs = [];
    for (const k of keys) {
        const tmp = [];
        try {
            const opts_ = Object.assign({ 'objects': true }, opts);
            const crypt = yamlcrypt.decrypt(k, opts_);
            crypt.safeLoadAll(content, obj => tmp.push(obj));
        } catch (e) {
            continue;
        }
        key = k;
        objs = tmp;
        break;
    }

    if (!key) {
        throw new Error('No matching key to decrypt the given data!');
    }

    if (!encryptionKey) {
        encryptionKey = key;
    }

    const reencrypt = (key !== encryptionKey);

    function processValues() {
    }

    let index = 0;
    const types = [];
    for (const obj of objs) {
        processValues(obj, null, v => v instanceof yamlcrypt.Plaintext, t => {
            const knownText = new _KnownText(t, index++, t.algorithm);
            types.push(_knownTextType(knownText, reencrypt));
            return knownText;
        });
    }

    _newTextTypes().forEach(t => types.push(t));

    const schema = yaml.Schema.create(types);
    const str = safeDumpAll(objs, { 'schema': schema });

    const transformed = callback(str);

    const result = [];
    yaml.safeLoadAll(transformed, obj => result.push(obj), { 'schema': schema });

    const crypt = yamlcrypt.encrypt(encryptionKey, opts);
    return crypt.safeDumpAll(result);
}

class _KnownText {
    constructor(plaintext, index, algorithm) {
        this.plaintext = plaintext;
        this.index = index;
        this.algorithm = algorithm;
    }
}

function _knownTextType(knownText, reencrypt) {
    return new yaml.Type('!yaml-crypt/:' + knownText.index, {
        kind: 'scalar',
        instanceOf: _KnownText,
        predicate: data => data.index === knownText.index,
        represent: data => data.plaintext.plaintext,
        construct: data => {
            if (!reencrypt && data === knownText.plaintext.plaintext) {
                return knownText.plaintext;
            } else {
                return new yamlcrypt.Plaintext(data, null, knownText.algorithm);
            }
        }
    });
}

function _newTextTypes() {
    const keys = [
        { 'type': '!yaml-crypt', 'algorithm': yamlcrypt.algorithms[0] }
    ];
    for (const algorithm of yamlcrypt.algorithms) {
        // also allow the usage of just the algorithm name, without version:
        const split = algorithm.split(':', 2);
        keys.push({ 'type': '!yaml-crypt/' + split[0], 'algorithm': algorithm });
        keys.push({ 'type': '!yaml-crypt/' + algorithm, 'algorithm': algorithm });
    }
    return keys.map(key => new yaml.Type(key.type, {
        kind: 'scalar',
        represent: data => data,
        construct: data => new yamlcrypt.Plaintext(data, null, key.algorithm)
    }));
}

module.exports.safeDumpAll = safeDumpAll;
module.exports.transform = transform;
