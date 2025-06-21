import 'package:flutter_test/flutter_test.dart';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';
import 'package:criptocracia/services/crypto_service.dart';

void main() {
  test('blind nonce produces verifiable signature', () async {
    final keyPair = await KeyPair.generate(null, 2048);
    final publicKey = keyPair.pk;
    final secretKey = keyPair.sk;

    final nonce = CryptoService.generateNonce();
    final hashed = CryptoService.hashNonce(nonce);
    final result = CryptoService.blindNonce(hashed, publicKey);

    final blindSig = secretKey.blindSign(
      null,
      result.blindMessage,
      Options.defaultOptions,
    );
    final sig = publicKey.finalize(
      blindSig,
      result.secret,
      result.messageRandomizer,
      hashed,
      Options.defaultOptions,
    );

    final valid = sig.verify(
      publicKey,
      result.messageRandomizer,
      hashed,
      Options.defaultOptions,
    );
    expect(valid, isTrue);
  });
}
