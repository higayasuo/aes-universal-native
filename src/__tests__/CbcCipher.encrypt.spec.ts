import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NativeCbcCipher } from '../NativeCbcCipher';
import { NodeCbcCipher } from './NodeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('CbcCipher.encrypt', () => {
  let mockCryptoModule: CryptoModule;
  let nativeCipher: NativeCbcCipher;
  let nodeCipher: NodeCbcCipher;

  beforeEach(() => {
    mockCryptoModule = {
      getRandomBytes: vi
        .fn()
        .mockImplementation((size) => new Uint8Array(size).fill(0x42)),
    } as unknown as CryptoModule;
    nativeCipher = new NativeCbcCipher(mockCryptoModule);
    nodeCipher = new NodeCbcCipher(mockCryptoModule);
  });

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should produce the same result across all implementations for %s',
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
      expect(nativeResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should handle empty plaintext consistently for %s',
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
      expect(nativeResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );

  it.each([
    ['A128CBC-HS256', 32],
    ['A192CBC-HS384', 48],
    ['A256CBC-HS512', 64],
  ] as const)(
    'should handle empty AAD consistently for %s',
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
      expect(nativeResult.iv).toEqual(new Uint8Array(16).fill(0x42));
    },
  );
});
