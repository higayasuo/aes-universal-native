import { describe, it, expect, vi } from 'vitest';
import { NodeCbcCipher } from 'aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBitLength: 128 },
  { enc: 'A192CBC-HS384', keyBitLength: 192 },
  { enc: 'A256CBC-HS512', keyBitLength: 256 },
] as const;

describe('CbcCipher.generateTag', () => {
  const getRandomBytes = vi
    .fn()
    .mockImplementation((size) => new Uint8Array(size).fill(0x42));
  const nativeCipher = new NativeCbcCipher(getRandomBytes);
  const nodeCipher = new NodeCbcCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should produce the same result across all implementations for %s',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBitLength / 8);
    },
  );

  it.each(keyConfigs)(
    'should handle key size %s consistently',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array([1, 2, 3]);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBitLength / 8);
    },
  );

  it.each(keyConfigs)(
    'should handle empty macData consistently for %s',
    async ({ keyBitLength }) => {
      const macRawKey = new Uint8Array(keyBitLength / 8).fill(0xaa);
      const macData = new Uint8Array(0);

      const nativeResult = await nativeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });
      const nodeResult = await nodeCipher.generateTag({
        macRawKey,
        macData,
        keyBitLength,
      });

      expect(nativeResult).toEqual(nodeResult);
      expect(nativeResult.length).toBe(keyBitLength / 8);
    },
  );
});
