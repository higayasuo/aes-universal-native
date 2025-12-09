import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NodeCbcCipher } from 'aes-universal-node';
import { NativeCbcCipher } from '../NativeCbcCipher';

const keyConfigs = [
  { enc: 'A128CBC-HS256', keyBitLength: 128 },
  { enc: 'A192CBC-HS384', keyBitLength: 192 },
  { enc: 'A256CBC-HS512', keyBitLength: 256 },
] as const;

describe('CbcCipher.generateTag', () => {
  const nativeCipher = new NativeCbcCipher();
  const nodeCipher = new NodeCbcCipher();

  describe('should produce the same result across all implementations', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBitLength }) => {
      const macRawKey = randomBytes(keyBitLength / 8);
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
    });
  });

  describe('should handle key size consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBitLength }) => {
      const macRawKey = randomBytes(keyBitLength / 8);
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
    });
  });

  describe('should handle empty macData consistently', () => {
    it.each(keyConfigs)('for $enc', async ({ keyBitLength }) => {
      const macRawKey = randomBytes(keyBitLength / 8);
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
    });
  });
});
