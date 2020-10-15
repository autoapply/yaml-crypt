const { homedir } = require("os");
const { readFile } = require("fs");
const { join } = require("path");

const yaml = require("js-yaml");

const {
  algorithms,
  isToken,
  generateKey,
  encrypt,
  decrypt
} = require("./crypto");
const {
  safeDumpAll,
  safeLoadAll,
  walkStringValues,
  walkValues,
  tryDecrypt
} = require("./utils");

async function loadFile(path, { config, loadAll } = { loadAll: false }) {
  const cfg = config ? config : await loadConfig();
  const content = await readFileAsync(path);
  const yc = yamlcrypt(cfg);
  return loadAll ? yc.decryptAll(content) : yc.decrypt(content);
}

async function loadConfig({ home, path } = {}) {
  let content = null;
  if (path) {
    content = await readFileAsync(path);
  } else {
    let h = home ? home : homedir();
    for (const filename of ["config.yaml", "config.yml"]) {
      try {
        content = await readFileAsync(join(h, ".yaml-crypt", filename));
        break;
      } catch (e) {
        if (e.code === "ENOENT") {
          continue;
        } else {
          throw e;
        }
      }
    }
  }
  if (content) {
    return yaml.safeLoad(content);
  } else {
    // default config
    return {};
  }
}

function readFileAsync(path) {
  return new Promise((resolve, reject) => {
    readFile(path, (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
}

function yamlcrypt({ keys, encryptionKey } = {}) {
  const normalizedKeys = normalizeKeys(keys);
  const normalizedEncryptionKey = normalizeKey(encryptionKey);
  return createYamlcrypt(normalizedKeys, normalizedEncryptionKey);
}

function normalizeKey(key) {
  const k = key && key.key !== undefined ? key : { key };
  if (k == null || k.key == null) {
    return null;
  }

  if (!k.source) {
    k.source = "unknown source";
  }

  if (typeof k.key !== "string") {
    throw new Error(`invalid key ${k.source}: ${typeof k.key}`);
  } else if (k.key.length === 0) {
    throw new Error(`empty key: ${k.source}`);
  } else {
    return k;
  }
}

function normalizeKeys(keys) {
  const arr = Array.isArray(keys)
    ? keys.map(normalizeKey)
    : [normalizeKey(keys)];
  return arr.filter(key => key != null);
}

function createYamlcrypt(keys, encryptionKey) {
  function mergeOpts(opts) {
    const result = Object.assign({}, opts);
    if (!Object.prototype.hasOwnProperty.call(result, "keys")) {
      result.keys = keys;
    }
    if (!Object.prototype.hasOwnProperty.call(result, "encryptionKey")) {
      result.encryptionKey = encryptionKey;
    }
    return result;
  }

  function trimStr(buf) {
    if (Buffer.isBuffer(buf)) {
      return buf.toString("ascii").trimRight();
    } else {
      return buf.trimRight();
    }
  }

  return {
    encrypt: (str, opts = {}) => {
      if (opts.raw) {
        return encrypt(
          opts.algorithm,
          (opts.encryptionKey || encryptionKey).key,
          str
        );
      } else {
        const obj = yaml.safeLoad(str);
        walkStringValues(obj, opts.path, s => new Plaintext(s));
        return yaml.safeDump(obj, yamlOpts(mergeOpts(opts)));
      }
    },

    encryptAll: (str, opts = {}) => {
      if (opts.raw) {
        return encrypt(
          opts.algorithm,
          (opts.encryptionKey || encryptionKey).key,
          str
        );
      } else {
        const objs = yaml.safeLoadAll(str);
        for (const obj of objs) {
          walkStringValues(obj, opts.path, s => new Plaintext(s));
        }
        return safeDumpAll(objs, yamlOpts(mergeOpts(opts)));
      }
    },

    decrypt: (str, opts = {}) => {
      if (opts.raw || isToken(str)) {
        const s = trimStr(str);
        const { decrypted } = tryDecrypt(
          algorithms,
          opts.keys || keys,
          (algorithm, key) => decrypt(algorithm, key.key, s)
        );
        return yaml.safeLoad(decrypted);
      } else {
        return yaml.safeLoad(str, yamlOpts(mergeOpts(opts)));
      }
    },

    decryptAll: (str, opts = {}) => {
      if (opts.raw || isToken(str)) {
        const s = trimStr(str);
        const { decrypted, key } = tryDecrypt(
          algorithms,
          opts.keys || keys,
          (algorithm, key) => decrypt(algorithm, key.key, s)
        );
        if (opts.callback) {
          opts.callback(key);
        }
        return safeLoadAll(decrypted);
      } else {
        return safeLoadAll(str, yamlOpts(mergeOpts(opts)));
      }
    },

    transform: (str, callback, opts = {}) => {
      if (opts.raw || isToken(str)) {
        const s = trimStr(str);
        const { key, algorithm, decrypted } = tryDecrypt(
          algorithms,
          opts.keys || keys,
          (algorithm, key) => decrypt(algorithm, key.key, s)
        );

        const transformed = callback(decrypted, key);

        if (transformed.toString() === decrypted) {
          return str;
        } else {
          return encrypt(algorithm, key.key, transformed);
        }
      } else {
        return doTransform(str, callback, mergeOpts(opts));
      }
    }
  };
}

function yamlOpts(opts) {
  const schema = createYamlSchema({
    keys: opts.keys,
    encryptionKey: opts.encryptionKey,
    algorithm: opts.algorithm,
    objects: !!opts.objects,
    base64: !!opts.base64,
    callback: opts.callback
  });
  return { schema };
}

function createYamlSchema({
  algorithm,
  keys,
  encryptionKey,
  objects,
  base64,
  callback
}) {
  const opts = { keys, encryptionKey, objects, base64, callback };
  const types = [];
  for (let i = 0; i < algorithms.length; i++) {
    const isDefault =
      algorithms[i] === algorithm || (algorithm == null && i === 0);
    types.push(
      createType(
        Object.assign({}, opts, {
          algorithm: algorithms[i],
          isDefault
        })
      )
    );
  }
  return yaml.Schema.create(types);
}

function createType({
  algorithm,
  isDefault,
  keys,
  encryptionKey,
  objects,
  base64,
  callback
}) {
  const name = "!yaml-crypt" + (algorithm == null ? "" : `/${algorithm}`);
  const type = new yaml.Type(name, {
    kind: "scalar",
    instanceOf: Plaintext,
    resolve: data => data !== null,
    construct: data => {
      const { decrypted, key } = tryDecrypt(
        [algorithm],
        keys,
        (algorithm, key) => decrypt(algorithm, key.key, data)
      );
      if (callback) {
        callback(key);
      }
      const decoded = base64
        ? Buffer.from(decrypted, "base64").toString("utf8")
        : decrypted;
      return objects ? new Plaintext(decoded, data, algorithm) : decoded;
    },
    predicate: data => {
      return (
        data.algorithm === algorithm || (data.algorithm == null && isDefault)
      );
    },
    represent: data => {
      let encrypted;
      if (data.ciphertext) {
        encrypted = data.ciphertext;
      } else {
        const str = data.toString();
        const encoded = base64 ? Buffer.from(str).toString("base64") : str;
        encrypted = encrypt(algorithm, encryptionKey.key, encoded);
      }
      return encrypted;
    }
  });
  return type;
}

function doTransform(str, callback, opts) {
  const { key, decrypted: docs } = tryDecrypt(
    algorithms,
    opts.keys,
    (algorithm, key) => {
      const o = Object.assign({}, opts);
      o.objects = true;
      o.algorithm = algorithm;
      o.keys = [key];
      return safeLoadAll(str, yamlOpts(o));
    }
  );

  if (!opts.encryptionKey) {
    opts.encryptionKey = key;
  }

  const reencrypting = key !== opts.encryptionKey;

  let index = 0;
  const types = [];
  for (const doc of docs) {
    walkValues(
      doc,
      null,
      v => v instanceof Plaintext,
      t => {
        const knownText = new KnownText(t.algorithm, t, index++);
        types.push(knownTextType(knownText, reencrypting));
        return knownText;
      }
    );
  }

  newTextTypes().forEach(t => types.push(t));

  const schema = yaml.Schema.create(types);
  const decrypted = safeDumpAll(docs, { schema: schema });

  const transformed = callback(decrypted, key);

  const result = safeLoadAll(transformed, { schema: schema });
  return safeDumpAll(result, yamlOpts(opts));
}

function knownTextType(knownText, reencrypt) {
  return new yaml.Type(`!yaml-crypt/:${knownText.index}`, {
    kind: "scalar",
    instanceOf: KnownText,
    predicate: data => data.index === knownText.index,
    represent: data => data.plaintext.plaintext,
    construct: data => {
      if (reencrypt || data !== knownText.plaintext.plaintext) {
        return new Plaintext(data, null, knownText.algorithm);
      } else {
        return knownText.plaintext;
      }
    }
  });
}

function newTextTypes() {
  const keys = [{ type: "!yaml-crypt", algorithm: algorithms[0] }];
  for (const algorithm of algorithms) {
    // also allow the usage of just the algorithm name, without version:
    const split = algorithm.split(":", 2);
    keys.push({ type: `!yaml-crypt/${split[0]}`, algorithm: algorithm });
    keys.push({ type: `!yaml-crypt/${algorithm}`, algorithm: algorithm });
  }
  return keys.map(
    key =>
      new yaml.Type(key.type, {
        kind: "scalar",
        construct: data => new Plaintext(data, null, key.algorithm)
      })
  );
}

class Plaintext {
  constructor(plaintext, ciphertext = null, algorithm = null) {
    this.plaintext = plaintext;
    this.ciphertext = ciphertext;
    this.algorithm = algorithm;
  }

  toString() {
    return this.plaintext;
  }
}

class KnownText {
  constructor(algorithm, plaintext, index) {
    this.algorithm = algorithm;
    this.plaintext = plaintext;
    this.index = index;
  }
}

module.exports = {
  algorithms,
  generateKey,
  loadFile,
  loadConfig,
  yamlcrypt,
  encrypt,
  decrypt
};
