import 'dart:convert';
import 'dart:typed_data';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';
import 'secure_storage_service.dart';

class VoterSessionService {
  static const _nonceKey = 'voter_nonce';
  static const _blindingResultKey = 'voter_blinding_result';

  static const _secureStorage = FlutterSecureStorage();

  static Future<void> saveSession(
    Uint8List nonce,
    BlindingResult result,
  ) async {
    await _secureStorage.write(key: _nonceKey, value: base64.encode(nonce));
    await _secureStorage.write(
      key: _blindingResultKey,
      value: jsonEncode(result.toJson()),
    );
  }

  static Future<Uint8List?> getNonce() async {
    final data = await _secureStorage.read(key: _nonceKey);
    if (data == null) return null;
    return base64.decode(data);
  }

  static Future<BlindingResult?> getBlindingResult() async {
    final data = await _secureStorage.read(key: _blindingResultKey);
    if (data == null) return null;
    return BlindingResult.fromJson(jsonDecode(data));
  }

  static Future<void> clearSession() async {
    await _secureStorage.delete(key: _nonceKey);
    await _secureStorage.delete(key: _blindingResultKey);
  }
}
