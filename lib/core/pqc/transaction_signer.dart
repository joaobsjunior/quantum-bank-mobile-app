import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import 'pqc_asn1.dart';

/// The device's post-quantum signing key (ML-DSA-65, FIPS 204). It is
/// separate from the TLS identity so the transport key can move to platform
/// hardware later without weakening the transaction signature, and it exists
/// in both transport modes.
class DeviceSigningKey {
  const DeviceSigningKey({
    required this.seed,
    required this.publicKey,
    required this.privateKey,
  });

  static const MlDsaLevel level = MlDsaLevel.mlDsa65;

  /// FIPS 204 context of the proof of possession sent with the CSR.
  static final Uint8List registrationContext = Uint8List.fromList(
    utf8.encode('quantum-bank-signing-key-v1'),
  );

  final Uint8List seed;
  final Uint8List publicKey;
  final Uint8List privateKey;

  String get algorithm => level.algorithmName;

  factory DeviceSigningKey.generate({Random? random}) {
    final rng = random ?? Random.secure();
    return DeviceSigningKey.fromSeed(
      Uint8List.fromList(
        List<int>.generate(32, (_) => rng.nextInt(256), growable: false),
      ),
    );
  }

  factory DeviceSigningKey.fromSeed(Uint8List seed) {
    final (publicKey, privateKey) = MlDsa.generateKeyPairSeeded(level.params, seed);
    return DeviceSigningKey(seed: seed, publicKey: publicKey, privateKey: privateKey);
  }

  Uint8List sign(Uint8List message, {required Uint8List context}) =>
      MlDsa.sign(privateKey, message, level.params, ctx: context);

  bool verify(Uint8List message, Uint8List signature, {required Uint8List context}) =>
      MlDsa.verify(publicKey, message, signature, level.params, ctx: context);

  /// The `signingKey` object of the CSR submission: the raw public key and a
  /// proof of possession over the DER CSR, which binds the signing key to the
  /// same OTK, subject and device that authorize the certificate.
  Map<String, Object?> registration({required Uint8List csrDer}) => {
    'alg': algorithm,
    'publicKey': base64.encode(publicKey),
    'proof': base64.encode(sign(csrDer, context: registrationContext)),
  };

  /// PKCS#8 seed-only PEM, for storage.
  String privateKeyPem() =>
      PqcAsn1.pem(PqcAsn1.pkcs8Label, PqcAsn1.privateKeyInfo(level, seed: seed));
}

/// Signs Pix orders with the [DeviceSigningKey] (contract `envelope-v1`):
/// the canonical message is `quantum-bank-pix-v1` followed by one line per
/// field, so the backend can rebuild it from the request without any JSON
/// canonicalization.
class PixTransactionSigner {
  PixTransactionSigner({
    DateTime Function()? clock,
    String Function()? nonceGenerator,
  }) : _clock = clock ?? (() => DateTime.now().toUtc()),
       _nonceGenerator = nonceGenerator ?? randomUuid;

  static const String algorithm = 'ML-DSA-65';
  static final Uint8List context = Uint8List.fromList(
    utf8.encode('quantum-bank-pix-v1'),
  );

  final DateTime Function() _clock;
  final String Function() _nonceGenerator;

  /// Returns the `signature` object to embed in the Pix request.
  Map<String, Object?> sign({
    required DeviceSigningKey key,
    required String subject,
    required String deviceId,
    required double amount,
    required String recipientKey,
    required String description,
    required String scenario,
  }) {
    final nonce = _nonceGenerator();
    final issuedAt = _clock().toUtc().toIso8601String();
    final message = canonicalMessage(
      subject: subject,
      deviceId: deviceId,
      amount: amount,
      recipientKey: recipientKey,
      description: description,
      scenario: scenario,
      nonce: nonce,
      issuedAt: issuedAt,
    );
    return {
      'alg': algorithm,
      'deviceId': deviceId,
      'nonce': nonce,
      'issuedAt': issuedAt,
      'value': base64.encode(key.sign(message, context: context)),
    };
  }

  static Uint8List canonicalMessage({
    required String subject,
    required String deviceId,
    required double amount,
    required String recipientKey,
    required String description,
    required String scenario,
    required String nonce,
    required String issuedAt,
  }) => Uint8List.fromList(
    utf8.encode(
      'quantum-bank-pix-v1\n$subject\n$deviceId\n${amount.toStringAsFixed(2)}\n'
      '$recipientKey\n$description\n$scenario\n$nonce\n$issuedAt\n',
    ),
  );

  /// RFC 4122 version 4 UUID from the platform CSPRNG.
  static String randomUuid({Random? random}) {
    final rng = random ?? Random.secure();
    final bytes = List<int>.generate(16, (_) => rng.nextInt(256));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-'
        '${hex.substring(16, 20)}-${hex.substring(20)}';
  }
}
