(function () {
    const is_browser = typeof window === "object";
    const is_node_js = !is_browser && typeof process === "object" && process.versions && process.versions.node;
    const is_worker = !is_browser && typeof self === "object" && self.postMessage;
    const is_common_js = typeof module === "object" && module.exports;
    const is_amd = typeof define === "function" && define.amd;

    const root = (is_browser && window) || (is_worker && self);

    const subtle = (root && root.crypto.subtle) || (is_node_js && require("crypto").subtle);
    if (!subtle) throw new Error("It appears that your browser does not support the SubtleCrypto API. Please upgrade to a newer browser that supports it.");

    const textEncoder = new TextEncoder();

    // HKDF info, to derive 2 keys for AES and HMAC
    const hkdfinfo_AESKey = textEncoder.encode("WebCrypto|AESKey");
    const hkdfinfo_HMACKey = textEncoder.encode("WebCrypto|HMACKey");

    // Argument checking
    const checkArg = (arg) => {
        if (typeof arg === "undefined" || arg === null) {
            return false;
        }
        return true;
    };

    // Concatenate Uint8Arrays
    function concatUint8Arrays(...arrays) {
        const u8arrays = [...arrays];
        const length = u8arrays.reduce((a, c) => a + c.length, 0);

        const newArray = new Uint8Array(length);
        let current = 0;
        u8arrays.forEach((arr) => {
            newArray.set(arr, current);
            current += arr.length;
        });

        return newArray;
    }

    async function deriveKeyPBKDF2(password, salt) {
        if (!checkArg(password) || !(typeof password === "string")) throw new TypeError("password must be a string");
        if (checkArg(salt) && !(salt instanceof Uint8Array))
            throw new TypeError("salt must be a Uint8Array");
        if (checkArg(salt) && salt.length !== 32)
            throw new Error("salt.length must be 32");
        
        const passwordBytes = textEncoder.encode(password);
        const passwordHash = await crypto.subtle.digest(
            "SHA-256",
            passwordBytes.buffer
        );

        const hashedKey = await crypto.subtle.importKey(
            "raw",
            passwordHash,
            "PBKDF2",
            false,
            ["deriveBits"]
        );
        const _salt = salt || crypto.getRandomValues(new Uint8Array(32));

        const pbkdf2Params = {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: _salt,
            iterations: 600_000,
        };

        const masterKeyBytes = await crypto.subtle.deriveBits(
            pbkdf2Params,
            hashedKey,
            32 * 8
        );
        const masterKey = await crypto.subtle.importKey(
            "raw",
            masterKeyBytes,
            "HKDF",
            false,
            ["deriveKey"]
        );
        return {
            masterKey: masterKey,
            salt: _salt
        };
    }

    async function deriveKeyRaw(keyData, salt) {
        if (!(keyData instanceof Uint8Array))
            throw new TypeError("keyData must be a Uint8Array");
        if (keyData.length !== 32) throw new Error("keyData.length must be 32");

        if (checkArg(salt) && !(salt instanceof Uint8Array))
            throw new TypeError("salt must be a Uint8Array");
        if (checkArg(salt) && salt.length !== 32)
            throw new Error("salt.length must be 32");

        const _salt = salt || crypto.getRandomValues(new Uint8Array(32));
        return {
            masterKey: await crypto.subtle.importKey(
                "raw",
                keyData,
                "HKDF",
                false,
                ["deriveKey"]
            ),
            salt: _salt,
        };
    }

    async function getKeysFromMasterKey(masterKey, salt) {
        const key_aes = await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: salt,
                info: hkdfinfo_AESKey,
            },
            masterKey,
            { name: "AES-CTR", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
        const key_hmac = await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: salt,
                info: hkdfinfo_HMACKey,
            },
            masterKey,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign", "verify"]
        );
        return {
            key_aes: key_aes,
            key_hmac: key_hmac,
        };
    }

    async function encryptPassword(data, password) {
        if (!checkArg(data) || !(data instanceof Uint8Array)) throw new Error("data must be a Uint8Array");
        const { masterKey, salt } = await deriveKeyPBKDF2(password);
        const { key_aes, key_hmac } = await getKeysFromMasterKey(
            masterKey,
            salt
        );

        const iv = new Uint8Array(16);
        crypto.getRandomValues(iv);

        const ciphertext = new Uint8Array(
            await subtle.encrypt(
                { name: "AES-CTR", counter: iv, length: 64 },
                key_aes,
                data
            )
        );
        const ciphertext_full_without_hmac = concatUint8Arrays(
            ciphertext,
            iv,
            salt
        );

        const hmac = new Uint8Array(
            await crypto.subtle.sign(
                "HMAC",
                key_hmac,
                ciphertext_full_without_hmac
            )
        );
        return concatUint8Arrays(ciphertext_full_without_hmac, hmac);
    }
    async function decryptPassword(data, password) {
        if (!checkArg(data) || !(data instanceof Uint8Array)) throw new Error("data must be a Uint8Array");
        if (data.length < 80) {
            throw new Error("Invalid ciphertext");
        }

        const ciphertext_full_without_hmac = data.slice(0, data.length - 32);

        const signature = data.slice(-32);
        const ciphertext = data.slice(0, data.length - 80);
        const iv = data.slice(ciphertext.length, data.length - 64);
        const salt = data.slice(ciphertext.length + 16, data.length - 32);

        const { masterKey } = await deriveKeyPBKDF2(password, salt);
        const { key_aes, key_hmac } = await getKeysFromMasterKey(
            masterKey,
            salt
        );

        const verified = await crypto.subtle.verify(
            "HMAC",
            key_hmac,
            signature,
            ciphertext_full_without_hmac
        );
        if (verified !== true) {
            throw new Error("Decryption error");
        }

        try {
            return new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-CTR", counter: iv, length: 64 },
                key_aes,
                ciphertext
            ));
        } catch (e) {
            throw new Error("Decryption error");
        }
    }

    async function encrypt(data, key) {
        if (!checkArg(data) || !(data instanceof Uint8Array)) throw new Error("data must be a Uint8Array");
        const { masterKey, salt } = await deriveKeyRaw(key);
        const { key_aes, key_hmac } = await getKeysFromMasterKey(
            masterKey,
            salt
        );
        const iv = new Uint8Array(16);
        crypto.getRandomValues(iv);

        const ciphertext = new Uint8Array(
            await subtle.encrypt(
                { name: "AES-CTR", counter: iv, length: 64 },
                key_aes,
                data
            )
        );
        const ciphertext_full_without_hmac = concatUint8Arrays(
            ciphertext,
            iv,
            salt
        );

        const hmac = new Uint8Array(
            await crypto.subtle.sign(
                "HMAC",
                key_hmac,
                ciphertext_full_without_hmac
            )
        );
        return concatUint8Arrays(ciphertext_full_without_hmac, hmac);
    }

    async function decrypt(data, key) {
        if (!checkArg(data) || !(data instanceof Uint8Array)) throw new Error("data must be a Uint8Array");
        if (!checkArg(key) || !(key instanceof Uint8Array)) throw new Error("key must be a Uint8Array");

        if (data.length < 80) {
            throw new Error("Invalid ciphertext");
        }

        const ciphertext_full_without_hmac = data.slice(0, data.length - 32);

        const signature = data.slice(-32);
        const ciphertext = data.slice(0, data.length - 80);
        const iv = data.slice(ciphertext.length, data.length - 64);
        const salt = data.slice(ciphertext.length + 16, data.length - 32);

        const { masterKey } = await deriveKeyRaw(key, salt);
        const { key_aes, key_hmac } = await getKeysFromMasterKey(
            masterKey,
            salt
        );

        const verified = await crypto.subtle.verify(
            "HMAC",
            key_hmac,
            signature,
            ciphertext_full_without_hmac
        );
        
        if (verified !== true) {
            throw new Error("Decryption error");
        }

        try {
            return new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-CTR", counter: iv, length: 64 },
                key_aes,
                ciphertext
            ));
        } catch (e) {
            throw new Error("Decryption error");
        }
    }
    if (is_common_js) {
        module.exports = {
            encrypt,
            decrypt,
            encryptPassword,
            decryptPassword
        }
    } else if ((is_browser || is_worker) && !is_amd) {
        root.js_encryption = {
            encrypt,
            decrypt,
            encryptPassword,
            decryptPassword
        }
    } else if (is_amd) {
        define(function() {
            return {
                encrypt,
                decrypt,
                encryptPassword,
                decryptPassword
            }
        });
    }
})();