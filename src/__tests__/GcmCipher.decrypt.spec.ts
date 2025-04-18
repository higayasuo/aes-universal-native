import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NodeGcmCipher } from 'expo-aes-universal-node';
import { NativeGcmCipher } from '../NativeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

const keyConfigs = [
  { enc: 'A128GCM', keyBytes: 16 },
  { enc: 'A192GCM', keyBytes: 24 },
  { enc: 'A256GCM', keyBytes: 32 },
] as const;

describe('GcmCipher.decrypt', () => {
  let mockCryptoModule: CryptoModule;
  let nativeCipher: NativeGcmCipher;
  let nodeCipher: NodeGcmCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    nativeCipher = new NativeGcmCipher(mockCryptoModule);
    nodeCipher = new NodeGcmCipher(mockCryptoModule);
  });

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %s',
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
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
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array(0);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
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
    async ({ enc, keyBytes }) => {
      const cek = new Uint8Array(keyBytes).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array(0);
      const { ciphertext, tag, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
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
