# js-encryption

## Simple encryption for JavaScript.

This module provides a simple way to encrypt data. Under the hood, it uses AES-256-CTR with HMAC-SHA256 to encrypt data. The encryption/decryption process was mainly taken from [php-encryption](https://github.com/defuse/php-encryption).

# Installation
## Browser
You can use script tags
```html
<script src="https://cdn.jsdelivr.net/npm/js-encryption@1.0.2/build/js-encryption.js" integrity="sha384-tUCTiDAKJFG5ZDi+9TdcpmXhkJR1N05r8vsNkezhb+cI2DUjl63TOrl7akJ1f9Cl" crossorigin="anonymous">
```
```js
js_encryption.encrypt(...);
```
or AMD
```js
require(["/path/to/js-encryption.js"], function(js_encryption) {
    js_encryption.encrypt(...)
});
```

## Node.js
You can use `require()` or `import`:
```js
const js_encryption = require("js-encryption");
```
```js
import { encryptPassword } from "js-encryption";
```

# Examples

## Encrypt and decrypt some data with a password
```js
const textEncoder = new TextEncoder();
const textDecoder = new TextEncoder();

const dataToEncrypt = textEncoder.encode("Super secret stuff");

js_encryption.encryptPassword(
    dataToEncrypt, 
    "ThisIsAVerySecurePassword"
)
    .then(encrypted => js_encryption.decryptPassword(encrypted, "ThisIsAVerySecurePassword"))
    .then(decrypted => console.log(textDecoder.decode(decrypted)));

```

## Encrypt and decrypt some data with a key
```js
const textEncoder = new TextEncoder();
const textDecoder = new TextEncoder();

const dataToEncrypt = textEncoder.encode("Super secret stuff");
const encryptionKey = new Uint8Array([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,21,23,24,25,26,27,28,29,30,31,32]);

js_encryption.encrypt(
    dataToEncrypt, 
    encryptionKey
)
    .then(encrypted => js_encryption.decryptPassword(encrypted, encryptionKey))
    .then(decrypted => console.log(textDecoder.decode(decrypted)));
```

# API

```js
encrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
```
Encrypts the data with the given key. Returns the encrypted ciphertext. The key must be 32 bytes long (for AES-256).
```js
decrypt(data: Uint8Array, key: Uint8Array): Promise<Uint8Array>
```
Decrypts the ciphertext from `encrypt()` (`data`) with the given key. Returns the decrypted data. The key must be 32 bytes long (for AES-256).

```js
encryptPassword(data: Uint8Array, password: String): Promise<Uint8Array>
```
Encrypts the data with the given password. Returns the encrypted ciphertext. The key must be 32 bytes long (for AES-256).   
   
   
```js
decryptPassword(data: Uint8Array, password: String): Promise<Uint8Array>
```

Decrypts the ciphertext from `encryptPassword()` (`data`) with the given password. Returns the decrypted data.

# License
```
MIT License

Copyright (c) 2023 rfl890

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```