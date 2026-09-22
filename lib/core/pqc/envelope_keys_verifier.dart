import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import 'hybrid_envelope.dart';
import 'mldsa_x509.dart';

/// Raised when the backend's envelope key set is not trustworthy.
class EnvelopeKeysUntrustedException implements Exception {
  const EnvelopeKeysUntrustedException(this.reason);

  final String reason;

  @override
  String toString() => 'EnvelopeKeysUntrustedException: $reason';
}

/// Turns the `envelopeKeys` object of the CSR response into a trusted
/// [EnvelopeKeySet]: the ML-DSA-65 signature over the canonical key set must
/// verify with the leaf of `signerChain`, the chain must verify up to the
/// bundled ML-DSA-87 root, and the leaf must be the backend identity. All of
/// it runs in Dart, so a platform TLS stack without ML-DSA cannot weaken it.
class EnvelopeKeysVerifier {
  EnvelopeKeysVerifier({
    required List<int> trustAnchorPem,
    required this.expectedSignerCommonName,
    DateTime Function()? clock,
  }) : _trustAnchorPem = utf8.decode(trustAnchorPem),
       _clock = clock ?? (() => DateTime.now().toUtc());

  /// FIPS 204 context string the backend uses for the key set signature.
  static final Uint8List signatureContext = Uint8List.fromList(
    utf8.encode('quantum-bank-envelope-keys-v1'),
  );

  final String _trustAnchorPem;
  final String expectedSignerCommonName;
  final DateTime Function() _clock;

  EnvelopeKeySet verify(Map<String, dynamic> envelopeKeys) {
    final now = _clock();
    final keySetJson = envelopeKeys['keySet'];
    final signature = envelopeKeys['signature'];
    final chainPems = envelopeKeys['signerChain'];
    if (keySetJson is! Map<String, dynamic> ||
        signature is! String ||
        chainPems is! List ||
        chainPems.isEmpty) {
      throw const EnvelopeKeysUntrustedException('envelopeKeys is incomplete');
    }

    final EnvelopeKeySet keySet;
    final MlDsaCertificate signer;
    try {
      keySet = EnvelopeKeySet.fromJson(keySetJson);
      final trustAnchor = MlDsaCertificate.fromPem(_trustAnchorPem);
      final chain = chainPems
          .cast<String>()
          .map(MlDsaCertificate.fromPem)
          .toList(growable: false);
      signer = MlDsaChainVerifier(trustAnchor: trustAnchor).verify(chain, now: now);
    } on EnvelopeException catch (error) {
      throw EnvelopeKeysUntrustedException(error.message);
    } on CertificateVerificationException catch (error) {
      throw EnvelopeKeysUntrustedException(error.message);
    }

    if (signer.commonName != expectedSignerCommonName) {
      throw EnvelopeKeysUntrustedException(
        'envelope keys signed by ${signer.commonName}, expected $expectedSignerCommonName',
      );
    }
    if (signer.isCa) {
      throw const EnvelopeKeysUntrustedException('envelope keys signed by a CA certificate');
    }
    final Uint8List signatureBytes;
    try {
      signatureBytes = base64.decode(signature);
    } on FormatException {
      throw const EnvelopeKeysUntrustedException('envelope keys signature is not base64');
    }
    final verified = MlDsa.verify(
      signer.publicKey,
      keySet.canonicalBytes(),
      signatureBytes,
      signer.publicKeyLevel.params,
      ctx: signatureContext,
    );
    if (!verified) {
      throw const EnvelopeKeysUntrustedException('envelope keys signature does not verify');
    }
    if (!keySet.isValidAt(now)) {
      throw const EnvelopeKeysUntrustedException('envelope key set already expired');
    }
    return keySet;
  }
}
