import 'dart:math';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import '../../core/pqc/pqc_asn1.dart';

/// Post-quantum device identity key pair (ML-DSA, FIPS 204).
///
/// [seed] is the 32-byte `xi` from which the pair was expanded; it is kept so
/// the PKCS#8 encoding can carry both the seed and the expanded private key.
class MlDsaKeyPair {
  const MlDsaKeyPair({
    required this.level,
    required this.publicKey,
    required this.privateKey,
    required this.seed,
  });

  final MlDsaLevel level;
  final Uint8List publicKey;
  final Uint8List privateKey;
  final Uint8List seed;

  String get algorithm => level.algorithmName;
}

class KeypairService {
  /// Generates a fresh ML-DSA key pair from the platform CSPRNG. ML-DSA-65
  /// (NIST category 3) is the `quantum-bank-mobile-client-v1` default; the
  /// PKI also accepts ML-DSA-87.
  MlDsaKeyPair generateMlDsaKeyPair({MlDsaLevel level = MlDsaLevel.mlDsa65}) {
    final seed = _secureSeed();
    final (publicKey, privateKey) = MlDsa.generateKeyPairSeeded(
      level.params,
      seed,
    );
    return MlDsaKeyPair(
      level: level,
      publicKey: publicKey,
      privateKey: privateKey,
      seed: seed,
    );
  }

  Uint8List _secureSeed() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256), growable: false),
    );
  }

  /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) carrying seed and expanded key.
  String encodePrivateKeyPem(MlDsaKeyPair keyPair) => PqcAsn1.pem(
    PqcAsn1.pkcs8Label,
    PqcAsn1.privateKeyInfo(
      keyPair.level,
      seed: keyPair.seed,
      expandedKey: keyPair.privateKey,
    ),
  );

  /// DER `SubjectPublicKeyInfo` for the pair, as embedded in the CSR.
  Uint8List encodeSubjectPublicKeyInfo(MlDsaKeyPair keyPair) =>
      PqcAsn1.subjectPublicKeyInfo(keyPair.level, keyPair.publicKey);
}
