const fs = require("fs");

const mocha = require("mocha");
const describe = mocha.describe;
const it = mocha.it;
const chai = require("chai");
const expect = chai.expect;

const crypto = require("../lib/crypto");

require("./crypto-util").setupCrypto();

describe("crypto", () => {
  it("should return the encrypted content (fernet)", () => {
    const result = crypto.encrypt(
      "fernet",
      "aehae5Ui0Eechaeghau9Yoh9jufiep7H",
      "Hello, world!"
    );
    expect(result).to.equal(
      "gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg=="
    );
  });

  it("should return the encrypted content (branca)", () => {
    const result = crypto.encrypt(
      "branca",
      "aehae5Ui0Eechaeghau9Yoh9jufiep7H",
      "Hello, world!"
    );
    expect(result).to.equal(
      "XUvrtHkyXTh1VUW885Ta4V5eQ3hBMFQMC3S3QwEfWzKWVDt3A5TnVUNtVXubi0fsAA8eerahpobwC8"
    );
  });

  it("should generate a key (branca)", () => {
    const result = crypto.generateKey("branca");
    expect(result).to.have.lengthOf(32);
  });

  it("should throw an error when passing null", () => {
    expect(() => crypto.decrypt("fernet", "", null)).to.throw(
      /message is null/
    );
  });

  it("should throw an error when passing invalid data", () => {
    expect(() => crypto.decrypt("fernet", "", {})).to.throw(
      /invalid type for message/
    );
  });

  it("should throw an error when passing invalid algorithm", () => {
    expect(() => crypto.decrypt("x", "", "")).to.throw(/unknown algorithm/);
  });

  it("should return the decrypted content (fernet)", () => {
    const key = "aehae5Ui0Eechaeghau9Yoh9jufiep7H";
    const encrypted =
      "gAAAAAAAAAABAAECAwQFBgcICQoLDA0OD7nQ_JQsjDx78n7mQ9bW3T-rgiTN7WX3Uq66EDA0qxZDNQppXL6WaOAIW4x8ElmcRg==";
    expect(crypto.decrypt("fernet", key, encrypted)).to.equal("Hello, world!");
  });

  it("should return the decrypted content (branca)", () => {
    const key = "aehae5Ui0Eechaeghau9Yoh9jufiep7H";
    const encrypted =
      "XUvrtHkyXTh1VUW885Ta4V5eQ3hBMFQMC3S3QwEfWzKWVDt3A5TnVUNtVXubi0fsAA8eerahpobwC8";
    expect(crypto.decrypt("branca", key, encrypted)).to.equal("Hello, world!");
  });

  it("should correctly identify valid tokens (fernet)", () => {
    expect(crypto.isToken("gAAAAAAAAAA")).to.equal(true);
    expect(crypto.isToken("gBBBB")).to.equal(true);
  });

  it("should correctly identify valid Buffer tokens (fernet)", () => {
    expect(crypto.isToken(Buffer.from("gAAAAAAAAAA"))).to.equal(true);
    expect(crypto.isToken(Buffer.from("gBBBB"))).to.equal(true);
  });

  it("should correctly identify valid string tokens (branca)", () => {
    const token = fs.readFileSync("./test/test-7.yaml-crypt").toString();
    expect(crypto.isToken(token)).to.equal(true);
  });

  it("should correctly identify valid Buffer tokens (branca)", () => {
    const token = fs.readFileSync("./test/test-7.yaml-crypt");
    expect(crypto.isToken(token)).to.equal(true);
  });

  it("should correctly identify invalid tokens", () => {
    expect(crypto.isToken("X")).to.equal(false);
    expect(crypto.isToken("XXX")).to.equal(false);
  });
});
