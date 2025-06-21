import 'dart:convert';
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:dart_nostr/dart_nostr.dart';
import 'package:nip59/nip59.dart';

class NostrService {
  static NostrService? _instance;
  static NostrService get instance {
    _instance ??= NostrService._internal();
    return _instance!;
  }

  bool _connected = false;
  bool _connecting = false;
  StreamSubscription? _eventSubscription;
  late Nostr _nostr;
  NostrKeyPairs? _currentKeyPair;

  NostrService._internal();

  // Keep the public constructor for backwards compatibility but make it return the singleton
  factory NostrService() => instance;

  Future<void> connect(String relayUrl) async {
    if (_connected) {
      debugPrint('🔗 Already connected to relay');
      return;
    }

    if (_connecting) {
      debugPrint('🔗 Connection already in progress, waiting...');
      // Wait for connection to complete
      int attempts = 0;
      while (_connecting && attempts < 30) {
        await Future.delayed(const Duration(milliseconds: 100));
        attempts++;
      }
      return;
    }

    try {
      _connecting = true;
      debugPrint('🔗 Attempting to connect to Nostr relay: $relayUrl');

      // Initialize dart_nostr with the relay
      _nostr = Nostr.instance;
      
      // Use timeout for relay initialization
      await Future.any([
        _nostr.services.relays.init(relaysUrl: [relayUrl]),
        Future.delayed(const Duration(seconds: 10)).then((_) => 
          throw TimeoutException('Relay connection timeout', const Duration(seconds: 10))),
      ]);

      // Connection established - dart_nostr doesn't expose connection status checking
      // The init method will throw an exception if connection fails

      _connected = true;
      debugPrint('✅ Successfully connected to Nostr relay: $relayUrl');
    } catch (e) {
      _connected = false;
      debugPrint('❌ Failed to connect to Nostr relay: $e');
      
      // Provide more specific error messages
      if (e is TimeoutException) {
        throw Exception('Connection timeout: Please check your internet connection and try again');
      } else if (e.toString().contains('WebSocket')) {
        throw Exception('WebSocket connection failed: Please check the relay URL and try again');
      } else {
        throw Exception('Failed to connect to Nostr relay: $e');
      }
    } finally {
      _connecting = false;
    }
  }

  Future<void> disconnect() async {
    if (!_connected) {
      debugPrint('🔗 Already disconnected from relays');
      return;
    }

    try {
      debugPrint('🔌 Disconnecting from Nostr relays...');
      
      // Cancel any active subscription
      await _eventSubscription?.cancel();
      _eventSubscription = null;

      // Close all relay connections with timeout
      await Future.any([
        _nostr.services.relays.disconnectFromRelays(),
        Future.delayed(const Duration(seconds: 5)),
      ]);

      _connected = false;
      _connecting = false;
      _currentKeyPair = null;
      debugPrint('✅ Disconnected from Nostr relays');
    } catch (e) {
      debugPrint('⚠️ Error disconnecting from Nostr relays: $e');
      // Force disconnection even if there was an error
      _connected = false;
      _connecting = false;
      _currentKeyPair = null;
    }
  }

  bool get isConnected => _connected;

  void loginPrivateKey({
    required String pubKeyHex,
    required String privKeyHex,
  }) {
    try {
      debugPrint('🔐 Attempting to login with:');
      debugPrint('   Public key: $pubKeyHex (${pubKeyHex.length} chars)');
      debugPrint('   Private key: ${privKeyHex.substring(0, 8)}... (${privKeyHex.length} chars)');

      // Validate private key format
      if (!_nostr.services.keys.isValidPrivateKey(privKeyHex)) {
        throw Exception('Invalid private key format');
      }

      // Validate key lengths
      if (pubKeyHex.length != 64) {
        throw Exception('Invalid public key length: expected 64 characters, got ${pubKeyHex.length}');
      }
      if (privKeyHex.length != 64) {
        throw Exception('Invalid private key length: expected 64 characters, got ${privKeyHex.length}');
      }

      // Generate key pair from private key using dart_nostr
      _currentKeyPair = _nostr.services.keys.generateKeyPairFromExistingPrivateKey(privKeyHex);
      
      // Validate that the generated public key matches the expected one
      if (_currentKeyPair!.public != pubKeyHex) {
        debugPrint('❌ Key mismatch:');
        debugPrint('   Expected: $pubKeyHex');
        debugPrint('   Generated: ${_currentKeyPair!.public}');
        throw Exception('Generated public key does not match expected key');
      }
      
      debugPrint('✅ Login successful');
    } catch (e) {
      debugPrint('❌ Login failed: $e');
      _currentKeyPair = null;
      rethrow;
    }
  }

  Future<void> sendBlindedNonce(
    String ecPublicKey,
    Uint8List blindedNonce,
  ) async {
    if (!_connected) throw Exception('Not connected to relay');
    debugPrint('Sending blinded nonce to EC: ${base64.encode(blindedNonce)}');
  }

  Future<void> sendBlindSignatureRequest({
    required String ecPubKey,
    required String electionId,
    required Uint8List blindedNonce,
    required String voterPrivKeyHex,
    required String voterPubKeyHex,
  }) async {
    // Ensure we're connected, but don't create a new connection if already connected
    if (!_connected) {
      debugPrint('🔗 Not connected, will connect first...');
      throw Exception('Not connected to relay. Please connect first.');
    }

    try {
      debugPrint('🔐 Logging in with voter keys...');
      loginPrivateKey(pubKeyHex: voterPubKeyHex, privKeyHex: voterPrivKeyHex);

      if (_currentKeyPair == null) {
        throw Exception('No current key pair available');
      }

      final payload = jsonEncode({
        'id': electionId,
        'kind': 1,
        'payload': base64.encode(blindedNonce),
      });

      debugPrint('📦 Creating NIP-59 gift wrap...');
      
      // Create NIP-59 gift wrap using the nip59 library
      final giftWrapEvent = await Nip59.createNIP59Event(
        payload,
        ecPubKey,
        voterPrivKeyHex,
        generateKeyPairFromPrivateKey: _nostr.services.keys.generateKeyPairFromExistingPrivateKey,
        generateKeyPair: _nostr.services.keys.generateKeyPair,
        isValidPrivateKey: _nostr.services.keys.isValidPrivateKey,
      );

      debugPrint('📡 Broadcasting event...');
      debugPrint('🔍 Gift wrap event details:');
      debugPrint('   ID: ${giftWrapEvent.id}');
      debugPrint('   Kind: ${giftWrapEvent.kind}');
      debugPrint('   PubKey: ${giftWrapEvent.pubkey}');
      debugPrint('   Created: ${giftWrapEvent.createdAt}');
      final signature = giftWrapEvent.sig;
      debugPrint('   Signature: $signature');
      if (signature != null) {
        debugPrint('   Signature length: ${signature.length}');
        
        // Validate signature format before broadcasting
        if (signature.length != 128) {
          throw Exception(
            'Invalid signature length: ${signature.length}, expected 128',
          );
        }
      } else {
        throw Exception('Event signature is null');
      }

      // Broadcast using dart_nostr
      _nostr.services.relays.sendEventToRelays(giftWrapEvent);

      // Add a small delay to allow the broadcast to complete
      await Future.delayed(const Duration(milliseconds: 500));

      debugPrint('✅ Sent wrapped event: ${giftWrapEvent.id}');
    } catch (e) {
      debugPrint('❌ Error sending blind signature request: $e');
      rethrow;
    }
  }

  /// Send blind signature request using the existing connection from the provider
  Future<void> sendBlindSignatureRequestSafe({
    required String ecPubKey,
    required String electionId,
    required Uint8List blindedNonce,
    required String voterPrivKeyHex,
    required String voterPubKeyHex,
  }) async {
    try {
      await sendBlindSignatureRequest(
        ecPubKey: ecPubKey,
        electionId: electionId,
        blindedNonce: blindedNonce,
        voterPrivKeyHex: voterPrivKeyHex,
        voterPubKeyHex: voterPubKeyHex,
      );
    } catch (e) {
      debugPrint('❌ Blind signature request failed: $e');
      // Don't rethrow to prevent UI crashes
    }
  }

  Future<void> castVote(
    String electionId,
    int candidateId,
    Uint8List signature,
  ) async {
    if (!_connected) throw Exception('Not connected to relay');
    debugPrint(
      'Casting vote for candidate $candidateId in election $electionId',
    );
  }

  Stream<NostrEvent> subscribeToElections() {
    if (!_connected) {
      throw Exception('Not connected to relay');
    }

    // Calculate DateTime for 24 hours ago
    final since = DateTime.now().subtract(const Duration(hours: 24));
    debugPrint('📅 Looking for kind 35000 events since: $since');

    // Create request filter for kind 35000 events from last 24 hours
    final filter = NostrFilter(
      kinds: [35000],
      since: since,
    );

    debugPrint('📡 Starting subscription for kind 35000 events...');

    // Create request using dart_nostr
    final request = NostrRequest(
      filters: [filter],
    );

    // Start subscription using dart_nostr
    final nostrStream = _nostr.services.relays.startEventsSubscription(
      request: request,
    );

    debugPrint('🎯 Subscription started, waiting for events...');

    // Convert dart_nostr events to our NostrEvent format
    return nostrStream.stream
        .map((dartNostrEvent) {
          debugPrint(
            '📥 Received event: kind=${dartNostrEvent.kind}, id=${dartNostrEvent.id}',
          );
          return dartNostrEvent;
        })
        .where((dartNostrEvent) {
          final hasContent = dartNostrEvent.content?.isNotEmpty ?? false;
          debugPrint(
            '🔍 Filtering event: kind=${dartNostrEvent.kind}, hasContent=$hasContent',
          );
          return (dartNostrEvent.id?.isNotEmpty ?? false) &&
              (dartNostrEvent.content?.isNotEmpty ?? false) &&
              (dartNostrEvent.tags?.isNotEmpty ?? false);
        })
        .map((dartNostrEvent) {
          debugPrint('✅ Processing valid event: ${dartNostrEvent.id}');
          return NostrEvent(
            id: dartNostrEvent.id ?? '',
            pubkey: dartNostrEvent.pubkey,
            createdAt: (dartNostrEvent.createdAt?.millisecondsSinceEpoch ?? DateTime.now().millisecondsSinceEpoch) ~/ 1000,
            kind: dartNostrEvent.kind ?? 0,
            tags: dartNostrEvent.tags?.map((tag) => tag.map((e) => e.toString()).toList()).toList() ?? [],
            content: dartNostrEvent.content ?? '',
            sig: dartNostrEvent.sig ?? '',
          );
        })
        .handleError((error) {
          debugPrint('🚨 Stream error: $error');
        })
        .asBroadcastStream(); // Make it a broadcast stream to allow multiple listeners
  }

  Stream<NostrEvent> subscribeToResults(String electionId) {
    if (!_connected) {
      throw Exception('Not connected to relay');
    }

    debugPrint('📊 Subscribing to results for election: $electionId');

    // Create filter for election results (kind 1 with election_id tag)
    final filter = NostrFilter(
      kinds: [1], // Regular text notes that contain results
      since: DateTime.now().subtract(const Duration(hours: 24)),
      e: [electionId], // Election event reference
      t: ['election_results'], // Type tag
    );

    debugPrint('📡 Starting results subscription...');

    final request = NostrRequest(
      filters: [filter],
    );

    final nostrStream = _nostr.services.relays.startEventsSubscription(
      request: request,
    );

    return nostrStream.stream
        .map((dartNostrEvent) {
          debugPrint('📥 Received result event: ${dartNostrEvent.id}');
          return dartNostrEvent;
        })
        .where((dartNostrEvent) {
          // Filter for valid result events
          final hasContent = dartNostrEvent.content?.isNotEmpty ?? false;
          final hasElectionTag = dartNostrEvent.tags?.any((tag) =>
              tag.length >= 2 && tag[0] == 'e' && tag[1] == electionId) ?? false;
          final hasResultTag = dartNostrEvent.tags?.any((tag) =>
              tag.length >= 2 && tag[0] == 't' && tag[1] == 'election_results') ?? false;
          
          debugPrint('🔍 Filtering result: content=$hasContent, election=$hasElectionTag, result=$hasResultTag');
          return hasContent && hasElectionTag && hasResultTag;
        })
        .map((dartNostrEvent) {
          debugPrint('✅ Processing valid result event: ${dartNostrEvent.id}');
          return NostrEvent(
            id: dartNostrEvent.id ?? '',
            pubkey: dartNostrEvent.pubkey,
            createdAt: (dartNostrEvent.createdAt?.millisecondsSinceEpoch ?? DateTime.now().millisecondsSinceEpoch) ~/ 1000,
            kind: dartNostrEvent.kind ?? 0,
            tags: dartNostrEvent.tags?.map((tag) => tag.map((e) => e.toString()).toList()).toList() ?? [],
            content: dartNostrEvent.content ?? '',
            sig: dartNostrEvent.sig ?? '',
          );
        })
        .handleError((error) {
          debugPrint('🚨 Results stream error: $error');
        })
        .asBroadcastStream();
  }

  Stream<NostrEvent> subscribeToBlindSignatures() {
    if (!_connected) {
      throw Exception('Not connected to relay');
    }

    if (_currentKeyPair == null) {
      throw Exception('No key pair available for subscription');
    }

    debugPrint('🔐 Subscribing to blind signatures for pubkey: ${_currentKeyPair!.public}');

    // Create filter for NIP-59 Gift Wrap events directed to our public key
    final filter = NostrFilter(
      kinds: [1059], // NIP-59 Gift Wrap events
      since: DateTime.now().subtract(const Duration(hours: 1)), // Only recent messages
      p: [_currentKeyPair!.public], // Messages directed to our pubkey
    );

    debugPrint('📡 Starting blind signatures subscription...');

    final request = NostrRequest(
      filters: [filter],
    );

    final nostrStream = _nostr.services.relays.startEventsSubscription(
      request: request,
    );

    return nostrStream.stream
        .map((dartNostrEvent) {
          debugPrint('📥 Received wrapped event: ${dartNostrEvent.id}');
          return dartNostrEvent;
        })
        .where((dartNostrEvent) {
          // Filter for valid wrapped events
          final hasContent = dartNostrEvent.content?.isNotEmpty ?? false;
          final hasPubkeyTag = dartNostrEvent.tags?.any((tag) =>
              tag.length >= 2 && tag[0] == 'p' && tag[1] == _currentKeyPair!.public) ?? false;
          final isGiftWrap = dartNostrEvent.kind == 1059;
          
          debugPrint('🔍 Filtering wrapped: content=$hasContent, pubkey=$hasPubkeyTag, giftWrap=$isGiftWrap');
          return hasContent && hasPubkeyTag && isGiftWrap;
        })
        .asyncMap((dartNostrEvent) async {
          try {
            debugPrint('🎁 Attempting to unwrap NIP-59 event: ${dartNostrEvent.id}');
            
            // Unwrap the NIP-59 Gift Wrap event using decryptNIP59Event
            // Convert dart_nostr event to nip59 compatible format
            final dartNostrEventForDecryption = dartNostrEvent;
            
            final decryptedEvent = await Nip59.decryptNIP59Event(
              dartNostrEventForDecryption,
              _currentKeyPair!.private,
              isValidPrivateKey: _nostr.services.keys.isValidPrivateKey,
            );
            
            final unwrappedPayload = decryptedEvent.content ?? '';
            
            debugPrint('📦 Successfully unwrapped payload: $unwrappedPayload');
            
            // Try to parse the payload as JSON to check if it's a blind signature response
            try {
              final payloadJson = jsonDecode(unwrappedPayload);
              if (payloadJson is Map<String, dynamic> && 
                  payloadJson.containsKey('blind_signature')) {
                debugPrint('✅ Found blind signature in payload');
                
                // Return the original event but with the unwrapped content
                return NostrEvent(
                  id: dartNostrEvent.id ?? '',
                  pubkey: dartNostrEvent.pubkey,
                  createdAt: (dartNostrEvent.createdAt?.millisecondsSinceEpoch ?? DateTime.now().millisecondsSinceEpoch) ~/ 1000,
                  kind: dartNostrEvent.kind ?? 0,
                  tags: dartNostrEvent.tags?.map((tag) => tag.map((e) => e.toString()).toList()).toList() ?? [],
                  content: unwrappedPayload, // Use unwrapped content
                  sig: dartNostrEvent.sig ?? '',
                );
              }
            } catch (e) {
              debugPrint('⚠️ Payload is not JSON or missing blind_signature: $e');
            }
            
            return null; // Not a blind signature response
          } catch (e) {
            debugPrint('❌ Failed to unwrap NIP-59 event: $e');
            return null;
          }
        })
        .where((event) => event != null)
        .cast<NostrEvent>()
        .handleError((error) {
          debugPrint('🚨 Blind signatures stream error: $error');
        })
        .asBroadcastStream();
  }

  Future<Uint8List?> waitForBlindSignature({
    Duration timeout = const Duration(seconds: 30),
  }) async {
    if (!_connected) {
      throw Exception('Not connected to relay');
    }

    if (_currentKeyPair == null) {
      throw Exception('No key pair available for waiting');
    }

    debugPrint('⏳ Waiting for blind signature (timeout: ${timeout.inSeconds}s)...');

    final completer = Completer<Uint8List?>();
    StreamSubscription? subscription;

    try {
      // Subscribe to blind signatures and wait for the first valid response
      subscription = subscribeToBlindSignatures().listen(
        (event) {
          try {
            debugPrint('🎯 Processing potential blind signature event');
            
            // Parse the unwrapped content
            final payloadJson = jsonDecode(event.content);
            if (payloadJson is Map<String, dynamic> && 
                payloadJson.containsKey('blind_signature')) {
              
              final blindSigBase64 = payloadJson['blind_signature'] as String;
              final blindSignature = base64.decode(blindSigBase64);
              
              debugPrint('✅ Received blind signature: ${blindSignature.length} bytes');
              
              if (!completer.isCompleted) {
                completer.complete(blindSignature);
              }
            } else {
              debugPrint('⚠️ Event content is not a valid blind signature response');
            }
          } catch (e) {
            debugPrint('❌ Error processing blind signature event: $e');
            if (!completer.isCompleted) {
              completer.completeError('Failed to process blind signature: $e');
            }
          }
        },
        onError: (error) {
          debugPrint('🚨 Blind signature subscription error: $error');
          if (!completer.isCompleted) {
            completer.completeError('Subscription error: $error');
          }
        },
      );

      // Set up timeout
      Timer(timeout, () {
        if (!completer.isCompleted) {
          debugPrint('⏰ Timeout waiting for blind signature');
          completer.complete(null);
        }
      });

      return await completer.future;
    } finally {
      await subscription?.cancel();
      debugPrint('🔚 Blind signature wait completed');
    }
  }
}

// Nostr event class (keeping our own for consistency)
class NostrEvent {
  final String id;
  final String pubkey;
  final int createdAt;
  final int kind;
  final List<List<String>> tags;
  final String content;
  final String sig;

  NostrEvent({
    required this.id,
    required this.pubkey,
    required this.createdAt,
    required this.kind,
    required this.tags,
    required this.content,
    required this.sig,
  });
}
