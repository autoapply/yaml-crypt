const fs = require("fs");
const path = require("path");

function walk(dir, recursive, callback) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const p = path.resolve(dir, file);
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      if (recursive) {
        walk(p, true, callback);
      }
    } else {
      callback(p);
    }
  }
}

module.exports.walk = walk;
