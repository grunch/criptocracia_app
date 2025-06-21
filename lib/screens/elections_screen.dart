import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/election.dart';
import '../providers/election_provider.dart';
import '../widgets/election_card.dart';
import 'election_detail_screen.dart';
import '../generated/app_localizations.dart';
import '../services/nostr_service.dart';
import '../services/nostr_key_manager.dart';
import '../services/crypto_service.dart';
import '../services/voter_session_service.dart';
import '../config/app_config.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:blind_rsa_signatures/blind_rsa_signatures.dart';

class ElectionsScreen extends StatefulWidget {
  const ElectionsScreen({super.key});

  @override
  State<ElectionsScreen> createState() => _ElectionsScreenState();
}

class _ElectionsScreenState extends State<ElectionsScreen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<ElectionProvider>().loadElections();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Consumer<ElectionProvider>(
        builder: (context, provider, child) {
          if (provider.isLoading) {
            return const Center(child: CircularProgressIndicator());
          }

          if (provider.error != null) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.error_outline,
                    size: 64,
                    color: Theme.of(context).colorScheme.error,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    AppLocalizations.of(
                      context,
                    ).errorWithMessage(provider.error!),
                    style: Theme.of(context).textTheme.bodyLarge,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton(
                    onPressed: () => provider.loadElections(),
                    child: Text(AppLocalizations.of(context).retry),
                  ),
                ],
              ),
            );
          }

          if (provider.elections.isEmpty) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(32),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      Icons.how_to_vote_outlined,
                      size: 80,
                      color: Theme.of(
                        context,
                      ).colorScheme.primary.withValues(alpha: 0.5),
                    ),
                    const SizedBox(height: 24),
                    Text(
                      AppLocalizations.of(context).noElectionsFound,
                      style: Theme.of(context).textTheme.headlineSmall
                          ?.copyWith(
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.onSurface,
                          ),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      AppLocalizations.of(context).noActiveElectionsFound,
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Theme.of(
                          context,
                        ).colorScheme.onSurface.withValues(alpha: 0.7),
                      ),
                    ),
                  ],
                ),
              ),
            );
          }

          return ListView.builder(
            padding: const EdgeInsets.all(16),
            itemCount: provider.elections.length,
            itemBuilder: (context, index) {
              final election = provider.elections[index];
              return ElectionCard(
                election: election,
                onTap: () async => await _navigateToElectionDetail(election),
              );
            },
          );
        },
      ),
    );
  }

  Future<void> _navigateToElectionDetail(Election election) async {
    if (election.status.toLowerCase() == 'open') {
      await _requestBlindSignature(election);
    }

    if (!mounted) return;

    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => ElectionDetailScreen(election: election),
      ),
    );
  }

  Future<void> _requestBlindSignature(Election election) async {
    try {
      final keys = await NostrKeyManager.getDerivedKeys();
      final privKey = keys['privateKey'] as Uint8List;
      final pubKey = keys['publicKey'] as Uint8List;

      String bytesToHex(Uint8List b) =>
          b.map((e) => e.toRadixString(16).padLeft(2, '0')).join();

      final voterPrivHex = bytesToHex(privKey);
      final voterPubHex = bytesToHex(pubKey);
      debugPrint('Voter private key (hex): $voterPrivHex');
      debugPrint('Voter public key (hex): $voterPubHex');

      final der = base64.decode(election.rsaPubKey);
      final ecPk = PublicKey.fromDer(der);

      final nonce = CryptoService.generateNonce();
      final hashed = CryptoService.hashNonce(nonce);
      final result = CryptoService.blindNonce(hashed, ecPk);

      await VoterSessionService.saveSession(nonce, result);

      // Use the shared NostrService instance to avoid concurrent connection issues
      final nostr = NostrService.instance;
      await nostr.sendBlindSignatureRequestSafe(
        ecPubKey: AppConfig.ecPublicKey,
        electionId: election.id,
        blindedNonce: result.blindMessage,
        voterPrivKeyHex: voterPrivHex,
        voterPubKeyHex: voterPubHex,
      );
    } catch (e) {
      debugPrint('❌ Error requesting blind signature: $e');
    }
  }
}
