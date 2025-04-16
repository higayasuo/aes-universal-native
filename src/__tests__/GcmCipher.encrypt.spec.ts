import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NativeGcmCipher } from '../NativeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('GcmCipher.encrypt', () => {
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

  it.each([
    ['A128GCM', 16],
    ['A192GCM', 24],
    ['A256GCM', 32],
  ] as const)(
    'should produce the same result across all implementations for %s (cek length: %d)',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
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

      expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(nativeResult.tag).toEqual(nodeResult.tag);
      expect(nativeResult.iv).toEqual(nodeResult.iv);
    },
  );

  it.each([
    ['A128GCM', 16],
    ['A192GCM', 24],
    ['A256GCM', 32],
  ] as const)(
    'should handle empty plaintext consistently for %s (cek length: %d)',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
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

      expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(nativeResult.tag).toEqual(nodeResult.tag);
      expect(nativeResult.iv).toEqual(nodeResult.iv);
    },
  );

  it.each([
    ['A128GCM', 16],
    ['A192GCM', 24],
    ['A256GCM', 32],
  ] as const)(
    'should handle empty AAD consistently for %s (cek length: %d)',
    async (enc, cekLength) => {
      const cek = new Uint8Array(cekLength).fill(0xaa);
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

      expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
      expect(nativeResult.tag).toEqual(nodeResult.tag);
      expect(nativeResult.iv).toEqual(nodeResult.iv);
    },
  );
});
