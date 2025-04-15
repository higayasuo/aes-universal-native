import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NativeGcmCipher } from '../NativeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

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

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should produce the same result across all implementations for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should handle empty ciphertext consistently for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should handle empty AAD consistently for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
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

  it.each(['A128GCM', 'A192GCM', 'A256GCM'] as const)(
    'should reject invalid tag for %s',
    async (enc) => {
      const cek = new Uint8Array(16).fill(0xaa);
      const plaintext = new Uint8Array([1, 2, 3]);
      const aad = new Uint8Array([4, 5, 6]);
      const { ciphertext, iv } = await nodeCipher.encrypt({
        enc,
        cek,
        plaintext,
        aad,
      });
      const invalidTag = new Uint8Array(16).fill(0xff);

      await expect(
        nativeCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
      await expect(
        nodeCipher.decrypt({
          enc,
          cek,
          ciphertext,
          tag: invalidTag,
          iv,
          aad,
        }),
      ).rejects.toThrow();
    },
  );
});
