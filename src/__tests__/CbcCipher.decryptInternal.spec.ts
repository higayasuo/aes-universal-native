import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NativeCbcCipher } from '../NativeCbcCipher';
import { NodeCbcCipher } from './NodeCbcCipher';
import { CryptoModule } from 'expo-crypto-universal';
import crypto from 'crypto';

describe('CbcCipher.decryptInternal', () => {
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

  it('should produce the same result across all implementations', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);

    // Encrypt using nodeCipher first
    const ciphertext = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    const nativeResult = await nativeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });

    expect(nativeResult).toEqual(nodeResult);
    expect(nativeResult).toEqual(plaintext);
  });

  it('should handle empty ciphertext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array(0);

    // Encrypt using nodeCipher first
    const ciphertext = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    const nativeResult = await nativeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });

    expect(nativeResult).toEqual(nodeResult);
    expect(nativeResult).toEqual(plaintext);
  });

  it('should handle block-aligned ciphertext with PKCS#7 padding consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(16).fill(0x42);
    const plaintext = new Uint8Array(1024).fill(0xaa);

    // Encrypt using nodeCipher first
    const ciphertext = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
    });

    const nativeResult = await nativeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });
    const nodeResult = await nodeCipher.decryptInternal({
      encRawKey,
      iv,
      ciphertext,
    });

    expect(nativeResult).toEqual(nodeResult);
    expect(nativeResult).toEqual(plaintext);
  });
});
