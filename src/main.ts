import { argon2id } from "hash-wasm";

const hkdfInfo = {
    encryptionKey: new TextEncoder().encode("WebCrypto|EncryptionKey"),
    hmacKey: new TextEncoder().encode("WebCrypto|HMACKey"),
};

async function hashPassword(
    password: string,
    salt: Uint8Array
): Promise<Uint8Array> {
    return await argon2id({
        password,
        salt,
        iterations: 1,
        parallelism: 1,
        memorySize: 47104,
        hashLength: 32,
        outputType: "binary",
    });
}

async function deriveKeys(
    masterKey: Uint8Array,
    salt: Uint8Array
): Promise<{ encryptionKey: CryptoKey; hmacKey: CryptoKey }> {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        masterKey,
        "HKDF",
        false,
        ["deriveBits"]
    );

    const encryptionKey = await crypto.subtle.importKey(
        "raw",
        await crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt,
                info: hkdfInfo.encryptionKey,
            },
            cryptoKey,
            32 * 8
        ),
        {
            name: "AES-CTR",
        },
        false,
        ["encrypt", "decrypt"]
    );

    const hmacKey = await crypto.subtle.importKey(
        "raw",
        await crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt,
                info: hkdfInfo.hmacKey,
            },
            cryptoKey,
            32 * 8
        ),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );

    return { encryptionKey, hmacKey };
}

export async function encryptPassword(
    plaintext: Uint8Array,
    password: string
): Promise<Uint8Array> {
    if (!(plaintext instanceof Uint8Array)) throw new Error("Plaintext must be a Uint8Array.");
    if (plaintext.length > 68719476736) throw new Error("Plaintext must be < 68719476736 bytes.");
    if (typeof password !== "string") throw new Error("Password must be a string.");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const counterBlock = new Uint8Array(16);
    counterBlock.set(iv, 0);

    const masterKey = await hashPassword(password, salt);
    const { encryptionKey, hmacKey } = await deriveKeys(masterKey, salt);

    const ciphertext = new Uint8Array(plaintext.length + 76);

    const encrypted = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: "AES-CTR",
                length: 32,
                counter: counterBlock,
            },
            encryptionKey,
            plaintext
        )
    );

    ciphertext.set(encrypted, 0);
    ciphertext.set(iv, plaintext.length);
    ciphertext.set(salt, plaintext.length + 12);

    const signature = new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            hmacKey,
            ciphertext.subarray(0, plaintext.length + 44)
        )
    );
    ciphertext.set(signature, plaintext.length + 44);

    return ciphertext;
}

export async function decryptPassword(
    ciphertext: Uint8Array,
    password: string
): Promise<Uint8Array> {
    if (!(ciphertext instanceof Uint8Array)) throw new Error("Ciphertext must be a Uint8Array.");
    if (typeof password !== "string") throw new Error("Password must be a string.");

    if (ciphertext.length < 76) throw new Error("Decryption error");
    if (ciphertext.length > (68719476736 + 76)) throw new Error("Decryption error");

    let offset = ciphertext.length - 76;

    const iv = ciphertext.slice(offset, offset + 12);
    offset += 12;
    const salt = ciphertext.slice(offset, offset + 32);
    offset += 32;
    const signature = ciphertext.slice(offset, ciphertext.length);

    const masterKey = await hashPassword(password, salt);
    const { encryptionKey, hmacKey } = await deriveKeys(masterKey, salt);

    const computedSignature = await crypto.subtle.verify(
        "HMAC",
        hmacKey,
        signature,
        ciphertext.subarray(0, -32)
    );
    if (!computedSignature) throw new Error("Decryption error");

    const counterBlock = new Uint8Array(16);
    counterBlock.set(iv, 0);

    try {
        const decrypted = await crypto.subtle.decrypt({
            name: "AES-CTR",
            length: 32,
            counter: counterBlock,
        }, encryptionKey, ciphertext.subarray(0, -76));
    
        return new Uint8Array(decrypted);
    } catch (e) {
        throw new Error("Decryption error");
    }
}

export async function encrypt(
    plaintext: Uint8Array,
    key: Uint8Array
): Promise<Uint8Array> {
    if (!(plaintext instanceof Uint8Array)) throw new Error("Plaintext must be a Uint8Array.");
    if (!(key instanceof Uint8Array)) throw new Error("Key must be a Uint8Array.");

    if (plaintext.length > 68719476736) throw new Error("The plaintext must be < 68719476736 bytes.");
    if (key.length !== 32) throw new Error("AES key length must be equal to 32 bytes");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const counterBlock = new Uint8Array(16);
    counterBlock.set(iv, 0);

    const { encryptionKey, hmacKey } = await deriveKeys(key, salt);

    const ciphertext = new Uint8Array(plaintext.length + 76);

    const encrypted = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: "AES-CTR",
                length: 32,
                counter: counterBlock,
            },
            encryptionKey,
            plaintext
        )
    );

    ciphertext.set(encrypted, 0);
    ciphertext.set(iv, plaintext.length);
    ciphertext.set(salt, plaintext.length + 12);

    const signature = new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            hmacKey,
            ciphertext.subarray(0, plaintext.length + 44)
        )
    );
    ciphertext.set(signature, plaintext.length + 44);

    return ciphertext;
}

export async function decrypt(
    ciphertext: Uint8Array,
    key: Uint8Array
): Promise<Uint8Array> {
    if (!(ciphertext instanceof Uint8Array)) throw new Error("Ciphertext must be a Uint8Array.");
    if (!(key instanceof Uint8Array)) throw new Error("Key must be a Uint8Array.");

    if (ciphertext.length < 76) throw new Error("Decryption error");
    if (ciphertext.length > (68719476736 + 76)) throw new Error("Decryption error");
    if (key.length !== 32) throw new Error("AES key length must be equal to 32 bytes");

    let offset = ciphertext.length - 76;

    const iv = ciphertext.slice(offset, offset + 12);
    offset += 12;
    const salt = ciphertext.slice(offset, offset + 32);
    offset += 32;
    const signature = ciphertext.slice(offset, ciphertext.length);

    const { encryptionKey, hmacKey } = await deriveKeys(key, salt);

    const computedSignature = await crypto.subtle.verify(
        "HMAC",
        hmacKey,
        signature,
        ciphertext.subarray(0, -32)
    );
    if (!computedSignature) throw new Error("Decryption error");

    const counterBlock = new Uint8Array(16);
    counterBlock.set(iv, 0);

    try {
        const decrypted = await crypto.subtle.decrypt({
            name: "AES-CTR",
            length: 32,
            counter: counterBlock,
        }, encryptionKey, ciphertext.subarray(0, -76));
    
        return new Uint8Array(decrypted);
    } catch (e) {
        throw new Error("Decryption error");
    }
}