const fs = require("fs");

const mocha = require("mocha");
const describe = mocha.describe;
const it = mocha.it;
const chai = require("chai");
const expect = chai.expect;

const tmp = require("tmp");

const { loadConfig, yamlcrypt } = require("../lib/yaml-crypt");

require("./crypto-util").setupCrypto();

describe("yaml-crypt", () => {
  it("should load the config file", () => {
    const config = loadConfig();
    expect(config).to.not.be.null;
  });

  it("should load the config file from the given path", () => {
    const configFile = tmp.fileSync();
    fs.writeFileSync(configFile.name, "keys:\n  - key: 123");
    const config = loadConfig({ path: configFile.name });
    expect(config).to.not.be.null;
  });

  it("should load the config file from home", () => {
    const home = tmp.dirSync();
    fs.mkdirSync(`${home.name}/.yaml-crypt`);
    fs.writeFileSync(
      `${home.name}/.yaml-crypt/config.yml`,
      "keys:\n  - key: 123"
    );
    const config = loadConfig({ home: home.name });
    expect(config).to.not.be.null;
    expect(config.keys).to.have.lengthOf(1);
  });

  it("should throw an error when the config file is not readable", () => {
    const home = tmp.dirSync();
    fs.mkdirSync(`${home.name}/.yaml-crypt`);
    fs.mkdirSync(`${home.name}/.yaml-crypt/config.yaml`);
    expect(() => loadConfig({ home: home.name })).to.throw(/illegal operation/);
  });

  it("should return the default config file", () => {
    const home = tmp.dirSync();
    const config = loadConfig({ home: home.name });
    expect(config).to.not.be.null;
    expect(config.keys).to.be.undefined;
  });

  it("should read the decrypted content", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-1b.yaml-crypt");
    const result = yaml.decrypt(content);
    expect(result.key1.toString()).to.equal("Hello, world!");
    expect(result.key2.toString()).to.equal("Hello, world!");
  });

  it("should read the decrypted raw content (string)", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-7.yaml-crypt");
    const result = yaml.decrypt(content);
    expect(result).to.equal("Hello!");
  });

  it("should read the decrypted raw content (Buffer)", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-7.yaml-crypt");
    const result = yaml.decryptAll(content.toString());
    expect(result[0]).to.equal("Hello!");
  });

  it("should return the encrypted content", () => {
    const yaml = yamlcrypt({
      encryptionKey: "aehae5Ui0Eechaeghau9Yoh9jufiep7H"
    });
    const str = '{ key1: "Hello, world!", key2: "Hello, world!" }';
    const result = yaml.encrypt(str);
    const expected = fs
      .readFileSync("./test/test-1a.yaml-crypt")
      .toString("utf8");
    expect(result).to.equal(expected);
  });

  it("should return the encrypted raw content", () => {
    const yaml = yamlcrypt({
      encryptionKey: "aehae5Ui0Eechaeghau9Yoh9jufiep7H"
    });
    const expected = fs
      .readFileSync("./test/test-7.yaml-crypt")
      .toString("utf8");
    const str = "Hello!";
    const result1 = yaml.encrypt(str, { algorithm: "branca", raw: true });
    const result2 = yaml.encryptAll(str, { algorithm: "branca", raw: true });
    expect(result1).to.equal(expected.trim());
    expect(result2).to.equal(expected.trim());
  });

  it("should return the base64 encrypted content", () => {
    const yaml = yamlcrypt({
      encryptionKey: "aehae5Ui0Eechaeghau9Yoh9jufiep7H"
    });
    const result = yaml.encryptAll("base64: Hello, world!", { base64: true });
    const expected = fs
      .readFileSync("./test/test-4.yaml-crypt")
      .toString("utf8");
    expect(result).to.equal(expected);
  });

  it("should read the decrypted base64 content", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-4.yaml-crypt");
    const result = yaml.decryptAll(content, { base64: true })[0];
    expect(result.base64.toString()).to.equal("Hello, world!");
  });

  it("should correctly transform the nested content", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-5.yaml-crypt");
    let decrypted = null;
    yaml.transform(content, str => (decrypted = str));
    expect(decrypted).to.contain("str: !<!yaml-crypt/:0> Hello!");
  });

  it("should re-encrypt transformed content", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content1 = fs.readFileSync("./test/test-6a.yaml-crypt");
    const content2 = fs.readFileSync("./test/test-6b.yaml-crypt");
    const transformed = yaml.transform(content1, str =>
      str.replace("Hello!", "Hello, world!")
    );
    expect(transformed).to.equal(content2.toString());
  });

  it("should encrypt new content when transforming", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const expected = fs.readFileSync("./test/test-1b.yaml-crypt");
    const newContent =
      "key1: !<!yaml-crypt/fernet> Hello, world!\nkey2: !<!yaml-crypt/branca> Hello, world!";
    const transformed = yaml.transform("", () => newContent);
    expect(transformed).to.equal(expected.toString());
  });

  it("should not re-encrypt unchanged content when transforming", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-7.yaml-crypt");
    const transformed = yaml.transform(content, str => str);
    expect(transformed).to.equal(content);
  });

  it("should re-encrypt transformed raw content", () => {
    const yaml = yamlcrypt({ keys: "aehae5Ui0Eechaeghau9Yoh9jufiep7H" });
    const content = fs.readFileSync("./test/test-7.yaml-crypt");
    const transformed = yaml.transform(content, str =>
      str.replace("Hello!", "Hello, world!")
    );
    expect(transformed).to.equal(
      "XUvrtHkyXTh1VUW885Ta4V5eQ3hBMFQMC3S3QwEfWzKWVDt3A5TnVUNtVXubi0fsAA8eerahpobwC8"
    );
  });

  it("should throw an error when an invalid key is given", () => {
    expect(() => yamlcrypt({ keys: 0 })).to.throw("invalid key: number");
  });

  it("should throw an error when an empty key is given", () => {
    expect(() => yamlcrypt({ keys: "" })).to.throw("empty key!");
  });
});
