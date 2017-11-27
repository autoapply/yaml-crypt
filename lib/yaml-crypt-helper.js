const yaml = require('js-yaml');

const yamlcrypt = require('./yaml-crypt');

function processStrings(obj, path, callback) {
    processValues(obj, path, v => typeof v === 'string', callback);
}

function processValues(obj, path, check, callback) {
    let subobj = obj;
    if (path) {
        const parts = path.split('.');
        for (let idx = 0; idx < parts.length; idx++) {
            const part = parts[idx];
            if (idx === parts.length - 1 && check(subobj[part])) {
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
            if (check(value)) {
                subobj[key] = callback(value);
            } else if (typeof value === 'object') {
                processValues(value, null, check, callback);
            }
        }
    }
}

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

function transform(content, keys, opts, callback) {
    let key = null;
    const objs = [];
    for (const k of keys) {
        try {
            const tmp = [];
            const opts_ = Object.assign({ 'objects': true }, opts);
            const crypt = yamlcrypt.decrypt(k, opts_);
            crypt.safeLoadAll(content, obj => tmp.push(obj));
            tmp.forEach(obj => objs.push(obj));
            key = k;
            break;
        } catch (e) {
            continue;
        }
    }

    if (key === null) {
        throw new Error('No matching key to decrypt the given data!');
    }

    let index = 0;
    const types = [];
    for (const obj of objs) {
        processValues(obj, null, v => v instanceof yamlcrypt.Plaintext, t => {
            const knownText = new _KnownText(t, index++);
            types.push(_knownTextType(key, knownText));
            return knownText;
        });
    }

    const schema = yaml.Schema.create(types);
    const str = safeDumpAll(objs, { 'schema': schema });

    const transformed = callback(str);

    const result = [];
    yaml.safeLoadAll(transformed, obj => result.push(obj), { 'schema': schema });

    const crypt = yamlcrypt.encrypt(key, opts);
    return crypt.safeDumpAll(result);
}

class _KnownText {
    constructor(plaintext, index) {
        this.plaintext = plaintext;
        this.index = index;
    }
}

function _knownTextType(key, knownText) {
    return new yaml.Type('!yaml-crypt/:' + knownText.index, {
        kind: 'scalar',
        instanceOf: _KnownText,
        predicate: data => data.index === knownText.index,
        represent: data => data.plaintext.plaintext,
        construct: data => {
            if (data === knownText.plaintext.plaintext) {
                return knownText.plaintext;
            } else {
                return new yamlcrypt.Plaintext(data);
            }
        }
    });
}

module.exports.processStrings = processStrings;
module.exports.processValues = processValues;
module.exports.safeDumpAll = safeDumpAll;
module.exports.transform = transform;
