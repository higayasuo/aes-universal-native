import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeCbcCipher } from 'aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

describe('CbcCipher.encrypt', () => {
  const nativeCipher = new NativeCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)('for $enc', async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle empty plaintext consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });

  describe('should handle empty AAD consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      expect(nativeResult).toEqual(nodeResult);
    });
  });
});
