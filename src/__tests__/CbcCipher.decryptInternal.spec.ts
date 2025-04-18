import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NodeCbcCipher } from 'expo-aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

describe('CbcCipher.decryptInternal', () => {
  let mockCryptoModule: CryptoModule;
  let nativeCipher: NativeCbcCipher;
  let nodeCipher: NodeCbcCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
      sha256Async: vi.fn().mockImplementation((data: Uint8Array) => {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return Promise.resolve(new Uint8Array(hash.digest()));
      }),
    } as unknown as CryptoModule;
    nativeCipher = new NativeCbcCipher(mockCryptoModule);
    nodeCipher = new NodeCbcCipher(mockCryptoModule);
  });

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %s',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array([1, 2, 3]);

      const ciphertext = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty ciphertext consistently for %s',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array(0);

      const ciphertext = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle block-aligned ciphertext with PKCS#7 padding consistently for %s',
    async ({ keyBytes }) => {
      const encRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const iv = new Uint8Array(16).fill(0x42);
      const plaintext = new Uint8Array(1024).fill(0xaa);

      const ciphertext = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );
});
