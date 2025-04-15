import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NativeGcmCipher } from '../NativeGcmCipher';
import { NodeGcmCipher } from './NodeGcmCipher';
import { CryptoModule } from 'expo-crypto-universal';

describe('GcmCipher.encryptInternal', () => {
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

  it('should produce the same result across all implementations', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array([4, 5, 6]);

    const nativeResult = await nativeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
  });

  it('should handle empty plaintext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array(0);
    const aad = new Uint8Array([4, 5, 6]);

    const nativeResult = await nativeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
  });

  it('should handle empty AAD consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const iv = new Uint8Array(12).fill(0x42);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array(0);

    const nativeResult = await nativeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encryptInternal({
      encRawKey,
      iv,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
  });
});
