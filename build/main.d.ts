export declare function encryptPassword(plaintext: Uint8Array, password: string): Promise<Uint8Array>;
export declare function decryptPassword(ciphertext: Uint8Array, password: string): Promise<Uint8Array>;
export declare function encrypt(plaintext: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
export declare function decrypt(ciphertext: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
