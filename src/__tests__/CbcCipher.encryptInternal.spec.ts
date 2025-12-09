import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeCbcCipher } from 'aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

describe('CbcCipher.encryptInternal', () => {
  const nativeCipher = new NativeCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(16);
      const plaintext = new Uint8Array([1, 2, 3]);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle empty plaintext consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(16);
      const plaintext = new Uint8Array(0);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle block-aligned plaintext with PKCS#7 padding consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(16);
      const plaintext = new Uint8Array(1024).fill(0xaa);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });
});
