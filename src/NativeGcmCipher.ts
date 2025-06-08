import {
  AbstractGcmCipher,
  GcmDecryptInternalParams,
  GcmEncryptInternalParams,
  GcmEncryptInternalResult,
  RandomBytes,
} from 'aes-universal';
import forge from 'node-forge';

/**
 * Class representing a Native GCM mode cipher implementation using node-forge.
 * Extends the AbstractGcmCipher class to provide AES-GCM encryption and decryption
 * functionality for native environments using the node-forge cryptographic library.
 */
export class NativeGcmCipher extends AbstractGcmCipher {
  /**
   * Constructs a NativeGcmCipher instance.
   * @param randomBytes - The random bytes function to be used for cryptographic operations.
   */
  constructor(randomBytes: RandomBytes) {
    super(randomBytes);
  }

  /**
   * Performs the internal encryption process using the AES-GCM algorithm via node-forge.
   * @param params - The arguments required for encryption, including the raw encryption key, IV, plaintext, and additional authenticated data.
   * @returns A promise that resolves to the encrypted data and authentication tag as a Uint8Array.
   * @throws Error if encryption fails or IV length is invalid
   */
  encryptInternal = async ({
    encRawKey,
    iv,
    plaintext,
    aad,
  }: GcmEncryptInternalParams): Promise<GcmEncryptInternalResult> => {
    if (iv.length !== 12) {
      throw new Error('IV must be 12 bytes for AES-GCM');
    }

    const encKeyBinary = forge.util.binary.raw.encode(encRawKey);
    const ivBinary = forge.util.binary.raw.encode(iv);
    const aadBinary = forge.util.binary.raw.encode(aad);
    const plaintextBinary = forge.util.binary.raw.encode(plaintext);
    const plaintextBuffer = forge.util.createBuffer(plaintextBinary);

    const cipher = forge.cipher.createCipher('AES-GCM', encKeyBinary);
    cipher.start({
      iv: ivBinary,
      additionalData: aadBinary,
      tagLength: 128,
    });

    cipher.update(plaintextBuffer);

    if (!cipher.finish()) {
      throw new Error('Encryption failed');
    }

    return {
      ciphertext: forge.util.binary.raw.decode(cipher.output.getBytes()),
      tag: forge.util.binary.raw.decode(cipher.mode.tag.getBytes()),
    };
  };

  /**
   * Performs the internal decryption process using the AES-GCM algorithm via node-forge.
   * @param params - The arguments required for decryption, including the raw encryption key, IV, ciphertext, authentication tag, and additional authenticated data.
   * @returns A promise that resolves to the decrypted data as a Uint8Array.
   * @throws Error if decryption fails, authentication fails, or IV length is invalid
   */
  decryptInternal = async ({
    encRawKey,
    iv,
    ciphertext,
    tag,
    aad,
  }: GcmDecryptInternalParams): Promise<Uint8Array> => {
    const encKeyBinary = forge.util.binary.raw.encode(encRawKey);
    const ivBinary = forge.util.binary.raw.encode(iv);
    const ciphertextBinary = forge.util.binary.raw.encode(ciphertext);
    const tagBinary = forge.util.binary.raw.encode(tag);
    const tagBuffer = forge.util.createBuffer(tagBinary);
    const aadBinary = forge.util.binary.raw.encode(aad);

    const decipher = forge.cipher.createDecipher('AES-GCM', encKeyBinary);

    decipher.start({
      iv: ivBinary,
      additionalData: aadBinary,
      tagLength: 128,
      tag: tagBuffer,
    });
    decipher.update(forge.util.createBuffer(ciphertextBinary));

    if (!decipher.finish()) {
      throw new Error('Authentication failed: Invalid tag or corrupted data');
    }

    return forge.util.binary.raw.decode(decipher.output.getBytes());
  };
}
