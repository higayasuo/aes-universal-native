import { AesCipher } from 'aes-universal';
import { NativeCbcCipher } from './NativeCbcCipher';
import { NativeGcmCipher } from './NativeGcmCipher';

/**
 * Native implementation of the AES cipher using node-forge.
 *
 * This class extends the base AesCipher class and provides implementations
 * for both CBC and GCM modes using node-forge functionality.
 */
export class NativeAesCipher extends AesCipher {
  constructor() {
    super({
      cbc: new NativeCbcCipher(),
      gcm: new NativeGcmCipher(),
    });
  }
}

/**
 * An instance of {@link NativeAesCipher}, providing AES encryption and decryption
 * using native (node-forge) implementations for CBC and GCM modes.
 */
export const nativeAesCipher = new NativeAesCipher();
