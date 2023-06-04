/**
 * Encrypts data with the given key.
 * 
 * @param data The data to encrypt
 * @param key The key to use to encrypt the data
 * 
 * @returns The encrypted ciphertext.
 */
export function encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

/**
 * Decrypts data with the given key.
 * 
 * @param data The data to decrypt
 * @param key The key to use to decrypt the data
 * 
 * @returns The decrypted data.
 */
export function decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>;

/**
 * Encrypts data with the given password.
 * 
 * @param data The data to encrypt
 * @param password The password to use the encrypt the data.
 * 
 * @returns The encrypted ciphertext.
 */
export function encryptPassword(data: Uint8Array, password: String): Promise<Uint8Array>;

/**
 * Decrypts data with the given password.
 * 
 * @param data The data to decrypt
 * @param password The password to use the decrypt the data.
 * 
 * @returns The decrypted data.
 */
export function decryptPassword(data: Uint8Array, password: String): Promise<Uint8Array>;