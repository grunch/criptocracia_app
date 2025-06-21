import 'package:bip39/bip39.dart' as bip39;
import 'package:elliptic/elliptic.dart';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:bech32/bech32.dart';
import 'package:blockchain_utils/bip/bip/bip32/bip32.dart';
import 'secure_storage_service.dart';
import 'dart:math';

/// Service for managing Nostr keys following NIP-06 specification
/// Generates mnemonic seed phrases and derives keys using m/44'/1237'/1989'/0/0 path
class NostrKeyManager {
  static const String _mnemonicKey = 'nostr_mnemonic';
  static const String _firstLaunchKey = 'first_launch_completed';
  static const String _derivationPath = "m/44'/1237'/1989'/0/0";

  /// Check if this is the first launch of the app
  static Future<bool> isFirstLaunch() async {
    final prefs = await SharedPreferences.getInstance();
    return !(prefs.getBool(_firstLaunchKey) ?? false);
  }

  /// Mark first launch as completed
  static Future<void> markFirstLaunchCompleted() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_firstLaunchKey, true);
  }

  /// Generate a new mnemonic seed phrase and store it securely
  static Future<String> generateAndStoreMnemonic() async {
    // Generate 12-word mnemonic (128 bits of entropy)
    final mnemonic = bip39.generateMnemonic();

    // Store mnemonic securely using our secure storage service
    await SecureStorageService.write(key: _mnemonicKey, value: mnemonic);

    return mnemonic;
  }

  /// Retrieve stored mnemonic seed phrase
  static Future<String?> getStoredMnemonic() async {
    return await SecureStorageService.read(key: _mnemonicKey);
  }

  /// Validate if a mnemonic is valid according to BIP39
  static bool validateMnemonic(String mnemonic) {
    return bip39.validateMnemonic(mnemonic);
  }

  /// Derive private key from mnemonic using NIP-06 specification
  /// Uses derivation path: m/44'/1237'/1989'/0/0
  /// Implements proper BIP32/BIP44 hierarchical deterministic key derivation
  static Future<Uint8List> derivePrivateKey(String mnemonic) async {
    if (!validateMnemonic(mnemonic)) {
      throw ArgumentError('Invalid mnemonic phrase');
    }

    try {
      // Convert mnemonic to seed (512 bits / 64 bytes) using BIP39
      final seed = bip39.mnemonicToSeed(mnemonic);
      
      // Create BIP32 master key from seed using secp256k1 curve (Bitcoin/Nostr standard)
      final masterKey = Bip32Slip10Secp256k1.fromSeed(seed);
      
      // Derive using NIP-06 path: m/44'/1237'/1989'/0/0
      // 44' = Purpose (BIP44)
      // 1237' = Coin type (Nostr)
      // 1989' = Account
      // 0 = Change (external chain)
      // 0 = Address index
      final derivedKey = masterKey
          .childKey(Bip32KeyIndex(44 + 0x80000000))    // Purpose: BIP44 (hardened)
          .childKey(Bip32KeyIndex(1237 + 0x80000000))  // Coin type: Nostr (hardened)
          .childKey(Bip32KeyIndex(1989 + 0x80000000))  // Account (hardened)
          .childKey(Bip32KeyIndex(0))                   // Change: external
          .childKey(Bip32KeyIndex(0));                  // Address index
      
      // Return the 32-byte private key as Uint8List
      final privateKeyBytes = Uint8List.fromList(derivedKey.privateKey.raw);
      
      if (privateKeyBytes.length != 32) {
        throw Exception('Derived private key must be 32 bytes, got ${privateKeyBytes.length}');
      }
      
      return privateKeyBytes;
    } catch (e) {
      throw Exception('Failed to derive private key using BIP32/BIP44: $e');
    }
  }

  /// Get public key from private key (32 bytes -> 32 bytes)
  static Uint8List getPublicKeyFromPrivate(Uint8List privateKey) {
    if (privateKey.length != 32) {
      throw ArgumentError('Private key must be 32 bytes');
    }

    // Use secp256k1 elliptic curve (used by Bitcoin and Nostr)
    final ec = getSecp256k1();

    // Convert private key bytes to hex string
    final privateKeyHex = privateKey
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join('');

    // Validate that the private key is within valid range for secp256k1
    final privateKeyBigInt = BigInt.parse(privateKeyHex, radix: 16);
    if (privateKeyBigInt >= ec.n || privateKeyBigInt == BigInt.zero) {
      throw ArgumentError('Private key is outside valid secp256k1 range');
    }

    // Create private key object and get public key
    final privKey = PrivateKey.fromHex(ec, privateKeyHex);
    final publicKey = privKey.publicKey;

    // Get the x-coordinate as hex (32 bytes for Nostr)
    final xCoordinate = publicKey.X.toRadixString(16).padLeft(64, '0');

    // Convert hex string back to Uint8List
    final bytes = <int>[];
    for (int i = 0; i < xCoordinate.length; i += 2) {
      bytes.add(int.parse(xCoordinate.substring(i, i + 2), radix: 16));
    }

    return Uint8List.fromList(bytes);
  }

  /// Convert public key to npub format using NIP-19 bech32 encoding
  static String publicKeyToNpub(Uint8List publicKey) {
    if (publicKey.length != 32) {
      throw ArgumentError('Public key must be 32 bytes');
    }

    try {
      // Convert the 32-byte public key to 5-bit groups for bech32 encoding
      final fiveBitData = _convertTo5BitGroups(publicKey);
      
      // Encode using bech32 with 'npub' prefix (NIP-19 specification)
      final bech32Result = bech32.encode(Bech32('npub', fiveBitData));
      
      return bech32Result;
    } catch (e) {
      throw Exception('Failed to encode public key to npub format: $e');
    }
  }

  /// Convert 8-bit bytes to 5-bit groups for bech32 encoding
  static List<int> _convertTo5BitGroups(Uint8List data) {
    final result = <int>[];
    int accumulator = 0;
    int bits = 0;
    
    for (final byte in data) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      
      while (bits >= 5) {
        result.add((accumulator >> (bits - 5)) & 31);
        bits -= 5;
      }
    }
    
    // Add padding if needed
    if (bits > 0) {
      result.add((accumulator << (5 - bits)) & 31);
    }
    
    return result;
  }

  /// Generate a simple test key pair for debugging
  static Map<String, dynamic> generateTestKeys() {
    final ec = getSecp256k1();

    // Generate a random private key using a simple approach
    final random = Random.secure();
    BigInt privateKeyBigInt;
    do {
      // Generate 32 random bytes for private key
      final bytes = List<int>.generate(32, (_) => random.nextInt(256));
      final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      privateKeyBigInt = BigInt.parse(hex, radix: 16);
    } while (privateKeyBigInt >= ec.n || privateKeyBigInt == BigInt.zero);

    final privateKey = PrivateKey.fromHex(
      ec,
      privateKeyBigInt.toRadixString(16).padLeft(64, '0'),
    );

    final publicKey = privateKey.publicKey;

    // Convert private key to hex string (64 chars)
    final privKeyHex = privateKey.D.toRadixString(16).padLeft(64, '0');

    // Convert private key to Uint8List (32 bytes)
    final privKeyBytes = <int>[];
    for (int i = 0; i < privKeyHex.length; i += 2) {
      privKeyBytes.add(int.parse(privKeyHex.substring(i, i + 2), radix: 16));
    }

    // Get x-coordinate as public key (32 bytes for Nostr)
    final xCoordinate = publicKey.X.toRadixString(16).padLeft(64, '0');
    final pubKeyBytes = <int>[];
    for (int i = 0; i < xCoordinate.length; i += 2) {
      pubKeyBytes.add(int.parse(xCoordinate.substring(i, i + 2), radix: 16));
    }

    final pubKeyUint8List = Uint8List.fromList(pubKeyBytes);
    final npub = publicKeyToNpub(pubKeyUint8List);

    debugPrint('🧪 Generated test keys:');
    debugPrint('   Private: $privKeyHex');
    debugPrint('   Public: $xCoordinate');
    debugPrint('   npub: $npub');

    return {
      'privateKey': Uint8List.fromList(privKeyBytes),
      'publicKey': pubKeyUint8List,
      'npub': npub,
      'isTest': true,
    };
  }

  /// Get derived keys from stored mnemonic
  static Future<Map<String, dynamic>> getDerivedKeys() async {
    final mnemonic = await getStoredMnemonic();
    debugPrint('🔑 Retrieving mnemonic: $mnemonic');
    if (mnemonic == null) {
      throw StateError('No mnemonic found. Generate one first.');
    }

    try {
      final privateKey = await derivePrivateKey(mnemonic);
      final publicKey = getPublicKeyFromPrivate(privateKey);
      final npub = publicKeyToNpub(publicKey);

      return {
        'mnemonic': mnemonic,
        'privateKey': privateKey,
        'publicKey': publicKey,
        'npub': npub,
        'derivationPath': _derivationPath,
      };
    } catch (e) {
      debugPrint('❌ Error with derived keys: $e');
      throw Exception('Failed to derive keys from mnemonic: $e');
    }
  }

  /// Initialize keys on first app launch
  static Future<void> initializeKeysIfNeeded() async {
    if (await isFirstLaunch()) {
      await generateAndStoreMnemonic();
      await markFirstLaunchCompleted();

      // Validate the generated keys
      final keys = await getDerivedKeys();
      // Use debugPrint instead of print to avoid linting issues in production
      assert(() {
        debugPrint('🔑 Generated new Nostr mnemonic on first launch');
        debugPrint('📱 Derivation path: $_derivationPath');
        debugPrint('✅ Keys validated successfully');
        debugPrint('🌐 npub: ${keys['npub']}');
        return true;
      }());
    }
  }

  /// Import and store an existing mnemonic seed phrase
  static Future<void> importMnemonic(String mnemonic) async {
    // Validate the mnemonic first
    if (!bip39.validateMnemonic(mnemonic.trim())) {
      throw Exception('Invalid mnemonic seed phrase');
    }

    // Store the validated mnemonic securely
    await SecureStorageService.write(key: _mnemonicKey, value: mnemonic.trim());
  }

  /// Clear all stored keys (for testing or reset purposes)
  static Future<void> clearAllKeys() async {
    await SecureStorageService.delete(key: _mnemonicKey);
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_firstLaunchKey);
  }
}
