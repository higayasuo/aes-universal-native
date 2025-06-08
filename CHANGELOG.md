# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2025-06-08

### Added

- Implemented NativeAesCipher class that provides a unified interface for both CBC and GCM modes
- Added support for all AES key sizes (128, 192, 256 bits) in both CBC and GCM modes

### Changed

- Updated README.md to use constants for encryption algorithms
- Improved code example readability and maintainability
- Fixed incorrect JSDoc comment in NativeAesCipher.ts

## [0.1.7] - 2025-06-04

### Changed

- Changed the signature of `generateTag` in `NativeCbcCipher.ts` to use `keyBitLength` instead of `keyBits`.

## [0.1.6] - 2025-06-02

### Changed

- Renamed library to `aes-universal-native`
- Updated API to use `webCryptoModule` instead of `WebCryptoModule` class
- Changed cipher initialization to use `getRandomBytes` function directly

## [0.1.2] - 2025-04-18

### Added

- Initial implementation of native AES encryption and decryption
- Support for AES-128, AES-192, and AES-256 in both CBC and GCM modes
- Comprehensive test suite for all encryption modes
- Documentation with examples for all supported modes

### Changed

- Updated README.md to emphasize the importance of using the same AAD for encryption and decryption
- Improved code organization and documentation

### Removed

- Removed redundant test scripts from README.md
  - `npm run test:coverage`
  - `npm run typecheck`
  - `npm run lint`
