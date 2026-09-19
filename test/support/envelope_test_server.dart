import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as classical;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:quantum_bank_mobile/core/pqc/hybrid_envelope.dart';

/// Backend-side half of the envelope for tests: holds the ML-KEM-768 and
/// X25519 private keys, opens request envelopes and seals responses with the
/// same key schedule as the app. Also used by the interop fixture tool.
class EnvelopeTestServer {
  EnvelopeTestServer._({
    required this.keySet,
    required this.mlkemSeed,
    required this.mlkemPrivateKey,
    required this.x25519PrivateKey,
  });

  static Future<EnvelopeTestServer> create({
    String kid = 'test-kid-001',
    DateTime? notAfter,
    Uint8List? mlkemSeed,
    Uint8List? x25519Seed,
  }) async {
    final kem = PqcKem.kyber768;
    final seed = mlkemSeed ?? Uint8List.fromList(List<int>.generate(64, (i) => (i * 7 + 3) & 0xff));
    final (mlkemPublicKey, mlkemPrivateKey) = kem.generateKeyPair(seed);
    final x25519 = classical.X25519();
    final xSeed = x25519Seed ?? Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 5) & 0xff));
    final xPair = await x25519.newKeyPairFromSeed(xSeed);
    final xPublic = await xPair.extractPublicKey();
    return EnvelopeTestServer._(
      keySet: EnvelopeKeySet(
        kid: kid,
        mlkemPublicKey: mlkemPublicKey,
        x25519PublicKey: Uint8List.fromList(xPublic.bytes),
        notAfter: notAfter ?? DateTime.utc(2027, 1, 1),
      ),
      mlkemSeed: seed,
      mlkemPrivateKey: mlkemPrivateKey,
      x25519PrivateKey: Uint8List.fromList(await xPair.extractPrivateKeyBytes()),
    );
  }

  final EnvelopeKeySet keySet;
  final Uint8List mlkemSeed;
  final Uint8List mlkemPrivateKey;
  final Uint8List x25519PrivateKey;

  /// Opens a request envelope for [aad]; returns the plaintext (empty for a
  /// header-only request) and the response key.
  Future<(Uint8List, Uint8List)> open(EnvelopeMessage message, String aad) async {
    final mlkemSecret = PqcKem.kyber768.decapsulate(mlkemPrivateKey, message.mlkemCiphertext!);
    final x25519 = classical.X25519();
    final pair = await x25519.newKeyPairFromSeed(x25519PrivateKey);
    final shared = await x25519.sharedSecretKey(
      keyPair: pair,
      remotePublicKey: classical.SimplePublicKey(
        message.x25519PublicKey!,
        type: classical.KeyPairType.x25519,
      ),
    );
    final (requestKey, responseKey) = HybridEnvelope.deriveKeys(
      mlkemSecret: mlkemSecret,
      x25519Secret: Uint8List.fromList(await shared.extractBytes()),
      kid: message.kid,
      aad: aad,
    );
    final ciphertext = message.ciphertext;
    final plaintext = ciphertext == null
        ? Uint8List(0)
        : HybridEnvelope.aesGcm(
            forEncryption: false,
            key: requestKey,
            nonce: message.nonce!,
            aad: utf8.encode(aad),
            input: ciphertext,
          );
    return (plaintext, responseKey);
  }

  EnvelopeMessage sealResponse({
    required Uint8List responseKey,
    required String kid,
    required String aad,
    required String body,
    String contentType = 'application/json',
    Uint8List? nonce,
  }) {
    final n = nonce ?? Uint8List.fromList(List<int>.generate(12, (i) => 200 - i));
    return EnvelopeMessage(
      kid: kid,
      nonce: n,
      ciphertext: HybridEnvelope.aesGcm(
        forEncryption: true,
        key: responseKey,
        nonce: n,
        aad: utf8.encode(aad),
        input: Uint8List.fromList(utf8.encode(body)),
      ),
      contentType: contentType,
    );
  }
}
