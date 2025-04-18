# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
