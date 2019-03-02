export as namespace yamlcrypt;

export const algorithms: Algorithm[];

/**
 * Generates a random key to be used with the given algorithm
 *
 * @param algorithm One of "fernet" (default) or "branca"
 * @returns A generated key, as string, suitable for the given algorithm
 */
export function generateKey(algorithm?: Algorithm): string;

/**
 * Loads the YAML file as object from the specified path,
 * using decryption keys from the user's configuration file
 *
 * @param path File path
 * @param opts Options to use while loading (optional)
 * @returns A promise that resolves to the loaded YAML document, as object
 */
export function loadFile(path: string, opts?: LoadFileOptions): Promise<any>;

export interface LoadFileOptions {
  /** Default decryption and encryption keys */
  config?: Config;

  /** Needs to be specified when the YAML file contains multiple documents */
  loadAll?: boolean;
}

/**
 * Load the user's configuration file from disk
 *
 * @param opts Options to use while loading (optional)
 * @returns A promise that resolves to the configuration object
 */
export function loadConfig(opts?: LoadConfigOptions): Promise<Config>;

export interface LoadConfigOptions {
  /** Full path of the configuration file */
  path?: string;

  /** Override user's HOME directory when loading */
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
  /**
   * Encrypts the given YAML document
   *
   * @param str The YAML document (as string) to encrypt
   * @param opts Encryption options
   * @returns The encrypted document, as string
   */
  encrypt(str: string, opts?: EncryptOptions): string;

  /**
   * Encrypts all the given YAML documents (multiple documents
   * are separated by "---")
   *
   * @param str The YAML documents (as string) to encrypt
   * @param opts Encryption options
   * @returns The encrypted documents, as string
   */
  encryptAll(str: string, opts?: EncryptOptions): string;

  /**
   * Decrypts the given YAML document, returns the parsed object
   *
   * @param str The YAML document (as string) to decrypt
   * @param opts Decryption options
   * @returns The decrypted document, as object
   */
  decrypt(str: string, opts?: DecryptOptions): any;

  /**
   * Decrypts all the given YAML documents (separated by "---"),
   * returns an array of parsed objects
   *
   * @param str The YAML documents (as string) to decrypt
   * @param opts Decryption options
   * @returns Array of the decrypted documents
   */
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
