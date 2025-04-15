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

  it('should produce the same result across all implementations', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array([4, 5, 6]);

    const nativeResult = await nativeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
    expect(nativeResult.iv).toEqual(nodeResult.iv);
  });

  it('should handle empty plaintext consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array(0);
    const aad = new Uint8Array([4, 5, 6]);

    const nativeResult = await nativeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
    expect(nativeResult.iv).toEqual(nodeResult.iv);
  });

  it('should handle empty AAD consistently', async () => {
    const encRawKey = new Uint8Array(16).fill(0xaa);
    const plaintext = new Uint8Array([1, 2, 3]);
    const aad = new Uint8Array(0);

    const nativeResult = await nativeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });
    const nodeResult = await nodeCipher.encrypt({
      enc: 'A128GCM',
      cek: encRawKey,
      plaintext,
      aad,
    });

    expect(nativeResult.ciphertext).toEqual(nodeResult.ciphertext);
    expect(nativeResult.tag).toEqual(nodeResult.tag);
    expect(nativeResult.iv).toEqual(nodeResult.iv);
  });
});
