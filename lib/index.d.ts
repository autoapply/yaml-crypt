export as namespace yamlcrypt;

export const algorithms: Algorithm[];

export function generateKey(algorithm?: Algorithm): string;

export function loadFile(path: string, opts?: LoadFileOptions): Promise<any>;

export interface LoadFileOptions {
  config?: Config;
  loadAll?: boolean;
}

export function loadConfig(opts?: LoadConfigOptions): Promise<Config>;

export interface LoadConfigOptions {
  path?: string;
  home?: string;
}

export function yamlcrypt(opts?: YamlcryptOptions): Yamlcrypt;

export type Algorithm = "fernet:0x80" | "fernet" | "branca:0xBA" | "branca";

export interface Config extends YamlcryptOptions {}

export interface YamlcryptOptions {
  keys?: Key | Key[];
  encryptionKey?: Key;
}

export type Key =
  | string
  | {
      key: string;
      name?: string;
    };

export interface Yamlcrypt {
  encrypt(str: string, opts?: EncryptOptions): string;

  encryptAll(str: string, opts?: EncryptOptions): string;

  decrypt(str: string, opts?: DecryptOptions): any;

  decryptAll(str: string, opts?: DecryptOptions): any[];

  transform(
    str: string,
    callback: (string) => string,
    opts?: EncryptOptions & DecryptOptions
  ): string;
}

export interface EncryptOptions {
  encryptionKey?: string;
  algorithm?: Algorithm;
  raw?: boolean;
  base64?: boolean;
}

export interface DecryptOptions {
  keys?: string[];
  base64?: boolean;
}
