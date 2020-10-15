const yaml = require("js-yaml");

class UsageError extends Error {}

function safeDumpAll(objs, opts) {
  let str = "";
  for (let idx = 0; idx < objs.length; idx++) {
    if (idx > 0) {
      str += "---\n";
    }
    str += yaml.safeDump(objs[idx], opts);
  }
  return str;
}

function safeLoadAll(str, opts) {
  // see https://github.com/nodeca/js-yaml/pull/381
  const objs = [];
  yaml.safeLoadAll(str, obj => objs.push(obj), opts);
  return objs;
}

function walkStringValues(obj, path, callback) {
  walkValues(obj, path, v => typeof v === "string", callback);
}

function walkValues(obj, path, check, callback) {
  let subobj = obj;
  if (path) {
    const parts = path.split(".");
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
    if (Object.prototype.hasOwnProperty.call(subobj, key)) {
      const value = subobj[key];
      if (check(value)) {
        subobj[key] = callback(value);
      } else if (typeof value === "object") {
        walkValues(value, null, check, callback);
      }
    }
  }
}

function tryDecrypt(algorithms, keys, decrypt) {
  if (!keys || !keys.length) {
    throw new UsageError("cannot decrypt data, no decryption keys given!");
  }
  let result = null;
  for (const algorithm of algorithms) {
    for (const key of keys) {
      try {
        const decrypted = decrypt(algorithm, key);
        result = { key, algorithm, decrypted };
        break;
      } catch (e) {
        continue;
      }
    }
  }
  if (result != null) {
    return result;
  } else {
    throw new UsageError("no matching key to decrypt the given data!");
  }
}

module.exports = {
  UsageError,
  safeDumpAll,
  safeLoadAll,
  walkValues,
  walkStringValues,
  tryDecrypt
};
