import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';
import 'package:pqcrypto/pqcrypto.dart';

import '../../core/pqc/pqc_asn1.dart';
import '../../core/tls/pqc_tls_support.dart';

/// A device identity key pair of one of the two families the PKI issues:
/// ML-DSA (post-quantum chain) or ECDSA P-256 (compatibility chain).
abstract interface class DeviceKeyPair {
  /// Canonical family name as the PKI prints it (`ML-DSA-65`, `ECDSA-P256`).
  String get algorithm;

  /// The transport mode this identity belongs to.
  TransportMode get transportMode;

  /// `SubjectPublicKeyInfo` to embed in the PKCS#10 request.
  ASN1Sequence subjectPublicKeyInfo();

  /// `AlgorithmIdentifier` of the proof-of-possession signature.
  ASN1Sequence signatureAlgorithmIdentifier();

  /// Signs [message] (the DER `CertificationRequestInfo`) with the private key.
  Uint8List sign(Uint8List message);

  /// PKCS#8 `PrivateKeyInfo` DER of the private key.
  Uint8List privateKeyInfo();
}

/// Post-quantum device identity key pair (ML-DSA, FIPS 204).
///
/// [seed] is the 32-byte `xi` from which the pair was expanded; the PKCS#8
/// encoding carries only the seed (RFC 9881 `seed` choice).
class MlDsaKeyPair implements DeviceKeyPair {
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

  @override
  String get algorithm => level.algorithmName;

  @override
  TransportMode get transportMode => TransportMode.postQuantum;

  @override
  ASN1Sequence subjectPublicKeyInfo() =>
      PqcAsn1.subjectPublicKeyInfoAsn1(level, publicKey);

  @override
  ASN1Sequence signatureAlgorithmIdentifier() =>
      PqcAsn1.algorithmIdentifier(level);

  /// Pure ML-DSA signature (empty context), the encoding OpenSSL >= 3.5 and
  /// BouncyCastle verify.
  @override
  Uint8List sign(Uint8List message) =>
      MlDsa.sign(privateKey, message, level.params);

  @override
  Uint8List privateKeyInfo() => PqcAsn1.privateKeyInfo(level, seed: seed);
}

/// Compatibility device identity: ECDSA on P-256, issued under the PKI's
/// ECDSA compatibility chain for platforms whose TLS stack cannot present
/// ML-DSA yet. Signatures are deterministic (RFC 6979) with SHA-256.
class EcdsaP256KeyPair implements DeviceKeyPair {
  const EcdsaP256KeyPair({required this.privateKey, required this.publicKey});

  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  @override
  String get algorithm => PqcAsn1.ecdsaP256AlgorithmName;

  @override
  TransportMode get transportMode => TransportMode.compatibility;

  /// Uncompressed point `04 || X || Y` (65 bytes).
  Uint8List get uncompressedPoint => publicKey.Q!.getEncoded(false);

  @override
  ASN1Sequence subjectPublicKeyInfo() =>
      PqcAsn1.ecSubjectPublicKeyInfoAsn1(uncompressedPoint);

  @override
  ASN1Sequence signatureAlgorithmIdentifier() =>
      PqcAsn1.ecdsaWithSha256AlgorithmIdentifier();

  @override
  Uint8List sign(Uint8List message) {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(true, PrivateKeyParameter<ECPrivateKey>(privateKey));
    final signature = signer.generateSignature(message) as ECSignature;
    return PqcAsn1.ecdsaSignature(signature.r, signature.s);
  }

  /// Verifies a DER-encoded ECDSA signature over [message] with this key.
  bool verify(Uint8List message, Uint8List derSignature) {
    final sequence = ASN1Parser(derSignature).nextObject() as ASN1Sequence;
    final r = (sequence.elements![0] as ASN1Integer).integer!;
    final s = (sequence.elements![1] as ASN1Integer).integer!;
    final verifier = ECDSASigner(SHA256Digest())
      ..init(false, PublicKeyParameter<ECPublicKey>(publicKey));
    return verifier.verifySignature(message, ECSignature(r, s));
  }

  @override
  Uint8List privateKeyInfo() => PqcAsn1.ecPrivateKeyInfo(
    scalar: PqcAsn1.scalarBytes(privateKey.d!),
    uncompressedPoint: uncompressedPoint,
  );
}

class KeypairService {
  /// Generates the identity for [mode]: ML-DSA-65 on a post-quantum capable
  /// platform, ECDSA P-256 on a compatibility platform.
  DeviceKeyPair generateForTransport(TransportMode mode) => switch (mode) {
    TransportMode.postQuantum => generateMlDsaKeyPair(),
    TransportMode.compatibility => generateEcdsaP256KeyPair(),
  };

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

  /// Generates a fresh ECDSA P-256 key pair for the compatibility chain,
  /// seeded from the platform CSPRNG.
  EcdsaP256KeyPair generateEcdsaP256KeyPair() {
    final random = FortunaRandom()..seed(KeyParameter(_secureSeed()));
    final generator = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(ECCurve_secp256r1()),
          random,
        ),
      );
    final pair = generator.generateKeyPair();
    return EcdsaP256KeyPair(
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
    );
  }

  Uint8List _secureSeed() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256), growable: false),
    );
  }

  /// PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) of the device private key.
  String encodePrivateKeyPem(DeviceKeyPair keyPair) =>
      PqcAsn1.pem(PqcAsn1.pkcs8Label, keyPair.privateKeyInfo());

  /// DER `SubjectPublicKeyInfo` for the pair, as embedded in the CSR.
  Uint8List encodeSubjectPublicKeyInfo(DeviceKeyPair keyPair) =>
      keyPair.subjectPublicKeyInfo().encode();
}
