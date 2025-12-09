import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeCbcCipher } from 'aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBytes: 16 },
  { enc: 'A192CBC-HS384', keyBytes: 24 },
  { enc: 'A256CBC-HS512', keyBytes: 32 },
] as const;

describe('CbcCipher.decrypt', () => {
  const nativeCipher = new NativeCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %s',
    async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));
      const { ciphertext, tag } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      const nativeResult = await nativeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty ciphertext consistently for %s',
    async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));
      const { ciphertext, tag } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      const nativeResult = await nativeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %s',
    async ({ enc }) => {
      const cek = randomBytes(nativeCipher.getCekByteLength(enc));
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const iv = randomBytes(nativeCipher.getIvByteLength(enc));
      const { ciphertext, tag } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });

      const nativeResult = await nativeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      const nodeResult = await nodeCipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult).toEqual(plaintext);
    },
  );
});
