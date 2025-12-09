import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeGcmCipher } from 'aes-universal-node';
import { NativeGcmCipher } from '../NativeGcmCipher';

const keyConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

describe('GcmCipher.decryptInternal', () => {
  const nativeCipher = new NativeGcmCipher();
  const nodeCipher = new NodeGcmCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)('for $enc', async ({ enc, keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(12);
      const { ciphertext, tag } = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    });
  });

  describe('should handle empty ciphertext consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ enc, keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(12);
      const { ciphertext, tag } = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    });
  });

  describe('should handle empty AAD consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ enc, keyBytes }) => {
      const encRawKey = randomBytes(keyBytes);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const iv = randomBytes(12);
      const { ciphertext, tag } = await nodeCipher.encryptInternal({
        encRawKey,
        iv,
        plaintext,
        aad,
      });

      const nativeResult = await nativeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });
      const nodeResult = await nodeCipher.decryptInternal({
        encRawKey,
        iv,
        ciphertext,
        tag,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    });
  });
});
