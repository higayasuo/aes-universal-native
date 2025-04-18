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

describe('CbcCipher.generateTag', () => {
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
      const macRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBytes);
    },
  );

  it.each(keyConfigs)(
    'should handle key size %s consistently',
    async ({ keyBytes }) => {
      const macRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBytes);
    },
  );

  it.each(keyConfigs)(
    'should handle empty macData consistently for %s',
    async ({ keyBytes }) => {
      const macRawKey = new Uint8Array(keyBytes).fill(0xaa);
      const macData = new Uint8Array(0);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBits: keyBytes * 8,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBytes);
    },
  );
});
