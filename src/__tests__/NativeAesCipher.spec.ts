import { describe, it, expect } from 'vitest';
import { randomBytes } from '@noble/hashes/utils';
import { NativeAesCipher } from '../NativeAesCipher';

const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const aad = new Uint8Array([9, 8, 7, 6]);

const keyConfigs = [
  { keyBitLength: 128, enc: 'A128CBC-HS256' },
  { keyBitLength: 192, enc: 'A192CBC-HS384' },
  { keyBitLength: 256, enc: 'A256CBC-HS512' },
  { keyBitLength: 128, enc: 'A128GCM' },
  { keyBitLength: 192, enc: 'A192GCM' },
  { keyBitLength: 256, enc: 'A256GCM' },
] as const;

describe('NativeAesCipher', () => {
  const cipher = new NativeAesCipher();

  describe('should encrypt and decrypt correctly', () => {
    it.each(keyConfigs)('for $enc', async ({ enc }) => {
      const cek = randomBytes(cipher.getCekByteLength(enc));
      const iv = randomBytes(cipher.getIvByteLength(enc));
      const { ciphertext, tag } = await cipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
        iv,
      });
      expect(ciphertext.length).toBeGreaterThan(0);
      expect(iv.length).toBe(enc.includes('GCM') ? 12 : 16);
      expect(tag.length).toBe(enc.includes('GCM') ? 16 : cek.length / 2);

      const decrypted = await cipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad,
      });
      expect(decrypted).toEqual(plaintext);
    });
  });

  it('should throw error when decrypting with invalid tag', async () => {
    const { enc } = keyConfigs[0];
    const cek = randomBytes(cipher.getCekByteLength(enc));
    const iv = randomBytes(cipher.getIvByteLength(enc));
    const { ciphertext } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
      iv,
    });

    const invalidTag = new Uint8Array(cek.length / 2).fill(0);

    await expect(
      cipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag: invalidTag,
        iv,
        aad,
      }),
    ).rejects.toThrow('Invalid authentication tag');
  });

  it('should throw error when decrypting with invalid iv', async () => {
    const { enc } = keyConfigs[0];
    const cek = randomBytes(cipher.getCekByteLength(enc));
    const iv = randomBytes(cipher.getIvByteLength(enc));
    const { ciphertext, tag } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
      iv,
    });

    const invalidIv = new Uint8Array(16).fill(0);

    await expect(
      cipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv: invalidIv,
        aad,
      }),
    ).rejects.toThrow('Invalid authentication tag');
  });

  it('should throw error when decrypting with invalid aad', async () => {
    const { enc } = keyConfigs[0];
    const cek = randomBytes(cipher.getCekByteLength(enc));
    const iv = randomBytes(cipher.getIvByteLength(enc));
    const { ciphertext, tag } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
      iv,
    });

    const invalidAad = new Uint8Array([1, 2, 3]);

    await expect(
      cipher.decrypt({
        enc,
        cek,
        ciphertext,
        tag,
        iv,
        aad: invalidAad,
      }),
    ).rejects.toThrow('Invalid authentication tag');
  });
});
