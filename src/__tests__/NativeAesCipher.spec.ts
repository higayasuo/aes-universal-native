import { describe, it, expect, vi } from 'vitest';
import { NativeAesCipher } from '../NativeAesCipher';
import { Enc } from 'aes-universal';

const getRandomBytes = vi
  .fn()
  .mockImplementation((size) => new Uint8Array(size).fill(0x42));

const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const aad = new Uint8Array([9, 8, 7, 6]);

const keyConfigs = [
  { cek: getRandomBytes(32), keyBitLength: 128, enc: 'A128CBC-HS256' as Enc },
  { cek: getRandomBytes(48), keyBitLength: 192, enc: 'A192CBC-HS384' as Enc },
  { cek: getRandomBytes(64), keyBitLength: 256, enc: 'A256CBC-HS512' as Enc },
  { cek: getRandomBytes(16), keyBitLength: 128, enc: 'A128GCM' as Enc },
  { cek: getRandomBytes(24), keyBitLength: 192, enc: 'A192GCM' as Enc },
  { cek: getRandomBytes(32), keyBitLength: 256, enc: 'A256GCM' as Enc },
];

describe('NativeAesCipher', () => {
  const cipher = new NativeAesCipher(getRandomBytes);

  it.each(keyConfigs)(
    'should encrypt and decrypt correctly',
    async ({ enc, cek }) => {
      const { ciphertext, tag, iv } = await cipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
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
    },
  );

  it('should throw error when decrypting with invalid tag', async () => {
    const { enc, cek } = keyConfigs[0];
    const { ciphertext, iv } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
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
    ).rejects.toThrow();
  });

  it('should throw error when decrypting with invalid iv', async () => {
    const { enc, cek } = keyConfigs[0];
    const { ciphertext, tag } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
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
    ).rejects.toThrow();
  });

  it('should throw error when decrypting with invalid aad', async () => {
    const { enc, cek } = keyConfigs[0];
    const { ciphertext, tag, iv } = await cipher.encrypt({
      enc,
      cek,
      plaintext,
      aad,
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
    ).rejects.toThrow();
  });
});
