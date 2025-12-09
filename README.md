# aes-universal-native

Native implementation of aes-universal.

## Installation

```bash
npm install aes-universal-native
```

## Peer Dependencies

This package requires the following peer dependencies:

- `aes-universal`: The base package that defines the interfaces
- `node-forge`: The crypto library

## Usage

`NativeAesCipher` provides AES encryption and decryption using native crypto implementation. It supports both CBC and GCM modes with various key sizes.

### CBC Mode

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A128CBC-HS256: 32 bytes (16 bytes for encryption + 16 bytes for MAC)
- A192CBC-HS384: 48 bytes (24 bytes for encryption + 24 bytes for MAC)
- A256CBC-HS512: 64 bytes (32 bytes for encryption + 32 bytes for MAC)

### GCM Mode

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A128GCM: 16 bytes
- A192GCM: 24 bytes
- A256GCM: 32 bytes

```typescript
import { nativeAesCipher } from 'aes-universal-native';
import { randomBytes } from '@noble/hashes/utils';

// Define encryption algorithms
const A128CBC_HS256 = 'A128CBC-HS256';
const A128GCM = 'A128GCM';

// Define plaintext and AAD
const plaintext = new Uint8Array([1, 2, 3, 4]);
const aad = new Uint8Array([5, 6, 7, 8]);

// Example with AES-128-CBC-HS256
const cekCbc = randomBytes(nativeAesCipher.getCekByteLength(A128CBC_HS256));
const ivCbc = randomBytes(nativeAesCipher.getIvByteLength(A128CBC_HS256));

// Encrypt data
const resultCbc = await nativeAesCipher.encrypt({
  enc: A128CBC_HS256, // AES-128 in CBC mode with HMAC-SHA-256
  cek: cekCbc,
  plaintext,
  aad,
  iv: ivCbc,
});

// Decrypt data
const decryptedCbc = await nativeAesCipher.decrypt({
  enc: A128CBC_HS256,
  cek: cekCbc,
  ciphertext: resultCbc.ciphertext,
  tag: resultCbc.tag,
  iv: ivCbc,
  aad,
});

expect(decryptedCbc).toEqual(plaintext);

// Example with AES-128-GCM
const cekGcm = randomBytes(nativeAesCipher.getCekByteLength(A128GCM));
const ivGcm = randomBytes(nativeAesCipher.getIvByteLength(A128GCM));

// Encrypt data
const resultGcm = await nativeAesCipher.encrypt({
  enc: A128GCM, // AES-128 in GCM mode
  cek: cekGcm,
  plaintext,
  aad,
  iv: ivGcm,
});

// Decrypt data
const decryptedGcm = await nativeAesCipher.decrypt({
  enc: A128GCM,
  cek: cekGcm,
  ciphertext: resultGcm.ciphertext,
  tag: resultGcm.tag,
  iv: ivGcm,
  aad,
});

expect(decryptedGcm).toEqual(plaintext);
```

## Development

### Setup

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

### Scripts

- `npm run build` - Build the library
- `npm test` - Run tests

## License

MIT
