const mocha = require("mocha");
const describe = mocha.describe;
const it = mocha.it;
const chai = require("chai");
const expect = chai.expect;

const utils = require("../lib/utils");

describe("utils", () => {
  it("should throw an error when no key is given", () => {
    expect(() => utils.tryDecrypt()).to.throw(/no decryption keys given/);
  });

  it("should split the path", () => {
    expect(utils.splitPath("a.b")).to.deep.equal(["a", "b"]);
    expect(utils.splitPath("a.b.c")).to.deep.equal(["a", "b", "c"]);
    expect(utils.splitPath("a.'b'")).to.deep.equal(["a", "b"]);
    expect(utils.splitPath('"a".b')).to.deep.equal(["a", "b"]);
    expect(utils.splitPath('"a.b".c')).to.deep.equal(["a.b", "c"]);
    expect(utils.splitPath("ab.cd[ef].gh")).to.deep.equal([
      "ab",
      "cd",
      "ef",
      "gh"
    ]);
    expect(utils.splitPath("a.b.'a.b'[a..s][a..]")).to.deep.equal([
      "a",
      "b",
      "a.b",
      "a..s",
      "a.."
    ]);
  });

  it("should return an error when splitting an invalid path", () => {
    expect(() => utils.splitPath("a.b[")).to.throw(/unmatched separator/);
  });
});
