const yaml = require("js-yaml");

class UsageError extends Error {}

function dump(obj, opts) {
  return yaml
    .dump(obj, opts)
    .replace(/!yaml-crypt\/([a-zA-Z0-9:]+)/g, "!<!yaml-crypt/$1>");
}

function dumpAll(objs, opts) {
  let str = "";
  for (let idx = 0; idx < objs.length; idx++) {
    if (idx > 0) {
      str += "---\n";
    }
    str += dump(objs[idx], opts);
  }
  return str;
}

function loadAll(str, opts) {
  // see https://github.com/nodeca/js-yaml/pull/381
  const objs = [];
  yaml.loadAll(str, obj => objs.push(obj), opts);
  return objs;
}

function splitPath(path) {
  const parts = [];
  const defaults = new RegExp(/(\."|\.'|\[|\.)/);
  let str = path[0] === '"' || path[0] === "'" ? "." + path : path;
  let next = defaults;
  while (str.length > 0) {
    const m = str.match(next);
    if (m == null) {
      break;
    } else {
      if (m.index > 0) {
        parts.push(str.substring(0, m.index));
      }
      const sep = m[0];
      if (sep === '."') {
        next = /"/;
      } else if (sep === ".'") {
        next = /'/;
      } else if (sep === "[") {
        next = /\]/;
      } else {
        next = defaults;
      }
      str = str.substring(m.index + sep.length);
    }
  }
  if (next === defaults) {
    if (str.length > 0) {
      parts.push(str);
    }
    return parts;
  } else {
    throw new Error("unmatched separator: " + next);
  }
}

function walkStringValues(obj, path, callback) {
  walkValues(obj, path, v => typeof v === "string", callback);
}

function walkValues(obj, path, check, callback) {
  let subobj = obj;
  if (path) {
    const parts = splitPath(path);
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
  dump,
  dumpAll,
  loadAll,
  splitPath,
  walkValues,
  walkStringValues,
  tryDecrypt
};
