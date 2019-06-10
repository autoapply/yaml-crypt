const mocha = require("mocha");
const describe = mocha.describe;
const it = mocha.it;
const chai = require("chai");
const expect = chai.expect;

const { walk } = require("../lib/yaml-crypt-helper");

describe("yaml-crypt-helper", () => {
  it("should throw an error", () => {
    expect(() => walk("./nonexistent", () => {})).to.throw(/ENOENT/);
  });

  it("should walk the directory", () => {
    const files = [];
    const callback = file => files.push(file);
    walk("./test", false, callback);
    expect(files).to.have.lengthOf(6);
  });

  it("should walk the directory recursively", () => {
    const files = [];
    const callback = file => files.push(file);
    walk("./test", true, callback);
    expect(files).to.have.lengthOf(15);
  });
});
