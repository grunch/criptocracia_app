import 'package:flutter_test/flutter_test.dart';
import 'package:dart_nostr/dart_nostr.dart';
import 'package:nip59/nip59.dart';

void main() {
  test('create NIP-59 gift wrap event and verify structure', () async {
    // Test configuration
    const recipientPubkey =
        '0000001ace57d0da17fc18562f4658ac6d093b2cc8bb7bd44853d0c196e24a9c';
    const senderPrivkey =
        '53b4bb170c8c2d1ffdb2c42e93d9a83e782669b0d6e34aba706b7bcac840c28b';
    const messageContent = 'hellowis';

    // Initialize dart_nostr
    final nostr = Nostr.instance;

    // Create NIP-59 gift wrap event using the nip59 library
    final giftWrapEvent = await Nip59.createNIP59Event(
      messageContent,
      recipientPubkey,
      senderPrivkey,
      generateKeyPairFromPrivateKey: nostr.services.keys.generateKeyPairFromExistingPrivateKey,
      generateKeyPair: nostr.services.keys.generateKeyPair,
      isValidPrivateKey: nostr.services.keys.isValidPrivateKey,
    );

    // Verify the gift wrap event structure
    expect(giftWrapEvent.kind, equals(1059)); // Gift wrap kind
    expect(giftWrapEvent.pubkey.length, equals(64)); // Valid pubkey length
    expect(giftWrapEvent.sig?.length ?? 0, equals(128)); // Valid signature length
    expect(giftWrapEvent.content?.isNotEmpty ?? false, isTrue); // Has encrypted content

    // Additional verification: check that the gift wrap was created for the correct recipient
    expect(
      giftWrapEvent.tags?.any(
        (tag) => tag.length >= 2 && tag[0] == 'p' && tag[1] == recipientPubkey,
      ) ?? false,
      isTrue,
      reason: 'Gift wrap should contain recipient pubkey in p tag',
    );

    // Verify the event has required fields
    expect(giftWrapEvent.id?.isNotEmpty ?? false, isTrue, reason: 'Event should have a valid ID');
    expect(giftWrapEvent.createdAt, isNotNull, reason: 'Event should have a creation timestamp');
  });

  test('decrypt NIP-59 gift wrap event', () async {
    // Test configuration
    const recipientPubkey =
        '0000001ace57d0da17fc18562f4658ac6d093b2cc8bb7bd44853d0c196e24a9c';
    const recipientPrivkey =
        '53b4bb170c8c2d1ffdb2c42e93d9a83e782669b0d6e34aba706b7bcac840c28b';
    const senderPrivkey =
        '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const originalMessage = 'test message for decryption';

    // Initialize dart_nostr
    final nostr = Nostr.instance;

    // Create NIP-59 gift wrap event
    final giftWrapEvent = await Nip59.createNIP59Event(
      originalMessage,
      recipientPubkey,
      senderPrivkey,
      generateKeyPairFromPrivateKey: nostr.services.keys.generateKeyPairFromExistingPrivateKey,
      generateKeyPair: nostr.services.keys.generateKeyPair,
      isValidPrivateKey: nostr.services.keys.isValidPrivateKey,
    );

    // Decrypt the gift wrap event
    final decryptedEvent = await Nip59.decryptNIP59Event(
      giftWrapEvent,
      recipientPrivkey,
      isValidPrivateKey: nostr.services.keys.isValidPrivateKey,
    );

    // Verify the decrypted content matches the original
    expect(decryptedEvent.content, equals(originalMessage),
        reason: 'Decrypted content should match original message');
    expect(decryptedEvent.kind, equals(1),
        reason: 'Original rumor should be kind 1');
  });
}
