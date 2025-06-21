# Criptocracia App Architecture

## Project Overview

Criptocracia is an experimental, trustless open-source electronic voting system built as a Flutter mobile application. The system implements blind RSA signatures for voter privacy and uses the Nostr protocol for decentralized communication.

## Core Technologies

- **Frontend**: Flutter (cross-platform mobile app)
- **Protocol**: Nostr (decentralized social network protocol)
- **Cryptography**: Blind RSA signatures, secp256k1 elliptic curve
- **Key Management**: BIP32/BIP44 hierarchical deterministic wallets
- **Storage**: Hive (encrypted local database) with hardware-backed security

## Architecture Components

### 1. Key Management (`lib/services/nostr_key_manager.dart`)

**Purpose**: Manages cryptographic keys following NIP-06 specification

**Key Features**:
- BIP39 mnemonic generation and validation
- BIP32/BIP44 hierarchical deterministic key derivation
- NIP-06 compliant derivation path: `m/44'/1237'/1989'/0/0`
- NIP-19 bech32 encoding for npub addresses
- Secure key storage integration

**Recent Improvements**:
- ✅ Replaced insecure XOR-based key derivation with proper BIP32/BIP44 implementation
- ✅ Added `blockchain_utils` library for cryptographically secure key derivation
- ✅ Implemented proper NIP-19 bech32 encoding instead of hex concatenation
- ✅ Fixed mnemonic generation to use new secure storage service

### 2. Secure Storage (`lib/services/secure_storage_service.dart`)

**Purpose**: Hardware-backed encrypted storage for sensitive data

**Key Features**:
- Device fingerprinting for hardware-backed security
- PBKDF2 key derivation (100,000 iterations)
- AES encryption with Hive database
- Platform-specific device identification
- Runtime key derivation (no hardcoded secrets)

**Security Improvements**:
- ✅ Replaced `flutter_secure_storage` with custom Hive-based solution
- ✅ Removed hardcoded secrets and implemented device-specific key derivation
- ✅ Added hardware-backed security with device fingerprinting

### 3. Nostr Communication (`lib/services/nostr_service.dart`)

**Purpose**: Handles Nostr protocol communication for voting operations

**Key Features**:
- dart_nostr library integration (migrated from NDK)
- NIP-59 Gift Wrap encryption for voter privacy
- Blind signature request handling
- Real-time event subscriptions
- Secure message encryption/decryption

**Migration History**:
- ✅ Migrated from NDK to dart_nostr library
- ✅ Integrated NIP-59 library for Gift Wrap functionality
- ✅ Maintained API compatibility during migration

### 4. Voter Session Management (`lib/services/voter_session_service.dart`)

**Purpose**: Manages voter session state and blind signature workflow

**Key Features**:
- Voter nonce generation and management
- Blind signature request/response handling
- Session state persistence
- Integration with secure storage

### 5. Application State (`lib/models/` and `lib/providers/`)

**Purpose**: Application-wide state management using Provider pattern

**Key Components**:
- Voter model with nonce and blind signature data
- Election data models
- Candidate selection state
- Results tracking

## Cryptographic Flow

### 1. Key Generation (First Launch)
```
Mnemonic (BIP39) → Seed → BIP32 Master Key → NIP-06 Derivation Path → Nostr Keys
```

### 2. Voting Process
```
1. Generate voter nonce
2. Create blind signature request
3. Send encrypted request via NIP-59 Gift Wrap
4. Receive blind signature from authority
5. Unblind signature and verify
6. Cast vote with verified signature
```

### 3. Nostr Communication
```
Private Key → Public Key → npub (NIP-19) → Nostr Identity → NIP-59 Encrypted Messages
```

## Dependencies

### Core Dependencies
- `flutter`: Cross-platform UI framework
- `dart_nostr: ^9.1.1`: Nostr protocol implementation
- `nip59`: NIP-59 Gift Wrap encryption (git dependency)
- `blind_rsa_signatures`: Blind signature implementation (git dependency)

### Cryptography
- `blockchain_utils: ^3.0.0`: BIP32/BIP44 key derivation
- `bip39: ^1.0.6`: Mnemonic generation and validation
- `bech32: ^0.2.2`: NIP-19 address encoding
- `elliptic: ^0.3.11`: Elliptic curve cryptography
- `crypto: ^3.0.6`: General cryptographic functions

### Storage & Security
- `hive: ^2.2.3`: Local database
- `hive_flutter: ^1.1.0`: Flutter integration for Hive
- `device_info_plus: ^10.1.2`: Device fingerprinting
- `shared_preferences: ^2.3.3`: Simple key-value storage

### State Management
- `provider: ^6.1.2`: State management solution

## Security Architecture

### 1. Hardware-Backed Security
- Device fingerprinting using platform-specific identifiers
- PBKDF2 key derivation with device-specific salt
- No hardcoded secrets or encryption keys

### 2. Cryptographic Standards
- **BIP32/BIP44**: Industry-standard hierarchical deterministic wallets
- **NIP-06**: Nostr key derivation specification
- **NIP-19**: Nostr address encoding
- **NIP-59**: Gift Wrap encryption for private messaging
- **secp256k1**: Bitcoin/Nostr standard elliptic curve

### 3. Key Management
- Mnemonic phrases stored in encrypted database
- Private keys derived on-demand (not stored)
- Secure key derivation following cryptographic best practices

## Development History

### Phase 1: Initial Implementation
- Basic Flutter app with counter functionality
- NDK integration for Nostr communication
- Initial blind signature implementation

### Phase 2: Security Hardening
- Migrated from NDK to dart_nostr
- Replaced flutter_secure_storage with Hive-based solution
- Implemented hardware-backed secure storage

### Phase 3: Cryptographic Compliance
- Fixed mnemonic generation workflow
- Implemented proper NIP-19 bech32 encoding
- Replaced insecure key derivation with BIP32/BIP44

### Current State
- ✅ Secure key management with industry standards
- ✅ NIP-06 compliant Nostr key derivation
- ✅ Hardware-backed encrypted storage
- ✅ NIP-59 encrypted communication
- ✅ Blind signature voting workflow

## Testing Strategy

### Unit Tests
- Key derivation and validation
- Cryptographic operations
- Storage encryption/decryption

### Integration Tests
- Nostr communication flow
- Blind signature workflow
- End-to-end voting process

### Security Tests
- Mnemonic generation and recovery
- Key derivation consistency
- Storage security validation

## Future Improvements

### Short Term
- Complete blind signature integration
- Enhanced error handling and user feedback
- Comprehensive test coverage

### Long Term
- Multi-election support
- Advanced voting schemes
- Audit trail implementation
- Performance optimization

## Configuration

### Development
```bash
flutter run --dart-define=debug=true
```

### Testing
```bash
flutter test --dart-define=CI=true
```

### Production Build
```bash
flutter build apk --release
```

## Notes for Future Development

1. **Key Management**: The current implementation follows NIP-06 and BIP standards. Any changes should maintain compatibility.

2. **Storage Security**: The secure storage service uses device-specific encryption. Changing the implementation requires careful migration.

3. **Nostr Integration**: The app uses dart_nostr with NIP-59 for encryption. Ensure compatibility when updating dependencies.

4. **Blind Signatures**: The voting workflow depends on proper blind signature implementation. Test thoroughly when making changes.

5. **Cross-Platform**: The app targets mobile platforms. Consider platform-specific security features when expanding.

## Troubleshooting

### Common Issues
- **Build failures**: Check dependency compatibility and Flutter version
- **Key derivation errors**: Verify mnemonic validation and BIP32 implementation
- **Storage issues**: Ensure device permissions and encryption key availability
- **Nostr connectivity**: Check relay URL and network connectivity

### Debug Commands
```bash
flutter analyze                    # Static analysis
flutter test                      # Run all tests
flutter pub deps                  # Dependency tree
flutter doctor                    # Environment check
```