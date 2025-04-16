# expo-aes-universal-native

Node.js implementation of expo-aes-universal for Expo applications.

## Installation

```bash
npm install expo-aes-universal-native
```

## Peer Dependencies

This package requires the following peer dependencies:

- `expo-aes-universal`: The base package that defines the interfaces
- `expo-crypto-universal`: The base package that defines the crypto interfaces
- `expo-crypto-universal-native`: Provides Node.js crypto implementation

```bash
npm install expo-aes-universal expo-crypto-universal expo-crypto-universal-native
```

## AES-128

### CBC Mode (A128CBC-HS256)

`NodeCbcCipher` provides AES-128-CBC encryption and decryption using Node.js crypto module.

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A128CBC-HS256: 32 bytes (16 bytes for encryption + 16 bytes for MAC)

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeCbcCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeCbcCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-128-CBC-HS256
const cek = await crypto.getRandomBytes(32); // 32 bytes (16 for encryption + 16 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A128CBC-HS256', // AES-128 in CBC mode with HMAC-SHA-256
  cek,
  plaintext,
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A128CBC-HS256',
  cek,
  ciphertext,
  tag,
  iv,
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A128GCM)

`NodeGcmCipher` provides AES-128-GCM encryption and decryption using Node.js crypto module.

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A128GCM: 16 bytes

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeGcmCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeGcmCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-128-GCM
const cek = await crypto.getRandomBytes(16); // 16 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A128GCM', // AES-128 in GCM mode
  cek,
  plaintext,
  aad: new Uint8Array([5, 6, 7, 8]), // Additional authenticated data
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A128GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad: new Uint8Array([5, 6, 7, 8]),
});

expect(decrypted).toEqual(plaintext);
```

## AES-192

### CBC Mode (A192CBC-HS384)

`NodeCbcCipher` provides AES-192-CBC encryption and decryption using Node.js crypto module.

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A192CBC-HS384: 48 bytes (24 bytes for encryption + 24 bytes for MAC)

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeCbcCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeCbcCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-192-CBC-HS384
const cek = await crypto.getRandomBytes(48); // 48 bytes (24 for encryption + 24 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A192CBC-HS384', // AES-192 in CBC mode with HMAC-SHA-384
  cek,
  plaintext,
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A192CBC-HS384',
  cek,
  ciphertext,
  tag,
  iv,
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A192GCM)

`NodeGcmCipher` provides AES-192-GCM encryption and decryption using Node.js crypto module.

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A192GCM: 24 bytes

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeGcmCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeGcmCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-192-GCM
const cek = await crypto.getRandomBytes(24); // 24 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A192GCM', // AES-192 in GCM mode
  cek,
  plaintext,
  aad: new Uint8Array([5, 6, 7, 8]), // Additional authenticated data
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A192GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad: new Uint8Array([5, 6, 7, 8]),
});

expect(decrypted).toEqual(plaintext);
```

## AES-256

### CBC Mode (A256CBC-HS512)

`NodeCbcCipher` provides AES-256-CBC encryption and decryption using Node.js crypto module.

In CBC mode, the Content Encryption Key (CEK) includes both the encryption key and the MAC key:

- A256CBC-HS512: 64 bytes (32 bytes for encryption + 32 bytes for MAC)

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeCbcCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeCbcCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-256-CBC-HS512
const cek = await crypto.getRandomBytes(64); // 64 bytes (32 for encryption + 32 for MAC)

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A256CBC-HS512', // AES-256 in CBC mode with HMAC-SHA-512
  cek,
  plaintext,
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A256CBC-HS512',
  cek,
  ciphertext,
  tag,
  iv,
});

expect(decrypted).toEqual(plaintext);
```

### GCM Mode (A256GCM)

`NodeGcmCipher` provides AES-256-GCM encryption and decryption using Node.js crypto module.

In GCM mode, the Content Encryption Key (CEK) is used directly for encryption:

- A256GCM: 32 bytes

```typescript
import { NodeCryptoModule } from 'expo-crypto-universal-native';
import { NodeGcmCipher } from 'expo-aes-universal-native';

// Create crypto module
const crypto = new NodeCryptoModule();

// Create cipher instance
const cipher = new NodeGcmCipher(crypto);

// Define plaintext
const plaintext = new Uint8Array([1, 2, 3, 4]);

// Generate random CEK for AES-256-GCM
const cek = await crypto.getRandomBytes(32); // 32 bytes

// Encrypt data
const { ciphertext, tag, iv } = await cipher.encrypt({
  enc: 'A256GCM', // AES-256 in GCM mode
  cek,
  plaintext,
  aad: new Uint8Array([5, 6, 7, 8]), // Additional authenticated data
});

// Decrypt data
const decrypted = await cipher.decrypt({
  enc: 'A256GCM',
  cek,
  ciphertext,
  tag,
  iv,
  aad: new Uint8Array([5, 6, 7, 8]),
});

expect(decrypted).toEqual(plaintext);
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
- `npm run test:coverage` - Run tests with coverage
- `npm run typecheck` - Run TypeScript type checking
- `npm run lint` - Run ESLint

## License

MIT
