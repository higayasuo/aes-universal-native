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
import { nativeCryptoModule } from 'expo-crypto-universal-native';
import { NativeAesCipher } from 'aes-universal-native';

// Random bytes function
const { getRandomBytes } = nativeCryptoModule;

// Define encryption algorithms
const A128CBC_HS256 = 'A128CBC-HS256';
const A128GCM = 'A128GCM';

// Create cipher instance
const cipher = new NativeAesCipher(getRandomBytes);

// Define plaintext and AAD
const plaintext = new Uint8Array([1, 2, 3, 4]);
const aad = new Uint8Array([5, 6, 7, 8]);

// Example with AES-128-CBC-HS256
const cekCbc = await cipher.generateCek(A128CBC_HS256);

// Encrypt data
const resultCbc = await cipher.encrypt({
  enc: A128CBC_HS256, // AES-128 in CBC mode with HMAC-SHA-256
  cek: cekCbc,
  plaintext,
  aad,
});

// Decrypt data
const decryptedCbc = await cipher.decrypt({
  enc: A128CBC_HS256,
  cek: cekCbc,
  ciphertext: resultCbc.ciphertext,
  tag: resultCbc.tag,
  iv: resultCbc.iv,
  aad,
});

expect(decryptedCbc).toEqual(plaintext);

// Example with AES-128-GCM
const cekGcm = await cipher.generateCek(A128GCM);

// Encrypt data
const resultGcm = await cipher.encrypt({
  enc: A128GCM, // AES-128 in GCM mode
  cek: cekGcm,
  plaintext,
  aad,
});

// Decrypt data
const decryptedGcm = await cipher.decrypt({
  enc: A128GCM,
  cek: cekGcm,
  ciphertext: resultGcm.ciphertext,
  tag: resultGcm.tag,
  iv: resultGcm.iv,
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
