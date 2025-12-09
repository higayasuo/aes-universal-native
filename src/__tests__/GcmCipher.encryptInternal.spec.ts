import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeGcmCipher } from 'aes-universal-node';
import { NativeGcmCipher } from '../NativeGcmCipher';

const keyConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

describe('GcmCipher.encryptInternal', () => {
  const nativeCipher = new NativeGcmCipher();
  const nodeCipher = new NodeGcmCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(12);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle empty plaintext consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(12);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle empty AAD consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const iv = randomBytes(12);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const nativeResult = await nativeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });
});
