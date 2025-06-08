import { AesCipher, RandomBytes } from 'aes-universal';
import { NativeCbcCipher } from './NativeCbcCipher';
import { NativeGcmCipher } from './NativeGcmCipher';

/**
 * Native implementation of the AES cipher using node-forge.
 *
 * This class extends the base AesCipher class and provides implementations
 * for both CBC and GCM modes using node-forge functionality.
 */
export class NativeAesCipher extends AesCipher<
  NativeCbcCipher,
  typeof NativeCbcCipher,
  NativeGcmCipher,
  typeof NativeGcmCipher
> {
  /**
   * Creates a new instance of NativeAesCipher.
   *
   * @param randomBytes - Function that generates cryptographically secure random bytes
   *                      Must implement the RandomBytes interface from aes-universal
   */
  constructor(randomBytes: RandomBytes) {
    super({
      cbc: NativeCbcCipher,
      gcm: NativeGcmCipher,
      randomBytes,
    });
  }
}
