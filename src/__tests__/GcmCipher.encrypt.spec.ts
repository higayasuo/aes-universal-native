import { describe, it, expect, vi } from 'vitest';
import { NodeGcmCipher } from 'aes-universal-node';
import { NativeGcmCipher } from '../NativeGcmCipher';

const keyConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

describe('GcmCipher.encrypt', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));
  const nativeCipher = new NativeGcmCipher(getRandomBytes);
  const nodeCipher = new NodeGcmCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %s',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle empty plaintext consistently for %s',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    },
  );

  it.each(keyConfigs)(
    'should handle empty AAD consistently for %s',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);

      const nativeResult = await nativeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const nodeResult = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });

      expect(nativeResult).toEqual(nodeResult);
    },
  );
});
