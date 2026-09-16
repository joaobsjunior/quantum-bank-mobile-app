import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';

/// Post-quantum signature levels accepted by the Quantum Bank PKI for the
/// `quantum-bank-mobile-client-v1` profile (FIPS 204).
enum MlDsaLevel {
  mlDsa65('ML-DSA-65', '2.16.840.1.101.3.4.3.18'),
  mlDsa87('ML-DSA-87', '2.16.840.1.101.3.4.3.19');

  const MlDsaLevel(this.algorithmName, this.oid);

  /// Canonical algorithm name as printed by OpenSSL and BouncyCastle.
  final String algorithmName;

  /// `id-ml-dsa-*` object identifier (NIST CSOR arc).
  final String oid;

  DilithiumParams get params => switch (this) {
    MlDsaLevel.mlDsa65 => DilithiumParams.mlDsa65,
    MlDsaLevel.mlDsa87 => DilithiumParams.mlDsa87,
  };
}

/// ASN.1 / PEM helpers for ML-DSA material. ML-DSA algorithm identifiers carry
/// no parameters (the OID alone selects the parameter set).
abstract final class PqcAsn1 {
  static const String pkcs8Label = 'PRIVATE KEY';
  static const String csrLabel = 'CERTIFICATE REQUEST';

  static ASN1Sequence algorithmIdentifier(MlDsaLevel level) => ASN1Sequence(
    elements: [ASN1ObjectIdentifier.fromIdentifierString(level.oid)],
  );

  /// `SubjectPublicKeyInfo { algorithm id-ml-dsa-*, subjectPublicKey BIT STRING }`.
  static Uint8List subjectPublicKeyInfo(MlDsaLevel level, Uint8List publicKey) =>
      ASN1Sequence(
        elements: [
          algorithmIdentifier(level),
          ASN1BitString(stringValues: publicKey),
        ],
      ).encode();

  /// PKCS#8 `PrivateKeyInfo` with the `both` choice of `ML-DSA-PrivateKey`
  /// (seed and expanded key), the form OpenSSL >= 3.5 and BouncyCastle accept.
  static Uint8List privateKeyInfo(
    MlDsaLevel level, {
    required Uint8List seed,
    required Uint8List expandedKey,
  }) {
    final both = ASN1Sequence(
      elements: [
        ASN1OctetString(octets: seed),
        ASN1OctetString(octets: expandedKey),
      ],
    );
    return ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.zero),
        algorithmIdentifier(level),
        ASN1OctetString(octets: both.encode()),
      ],
    ).encode();
  }

  static String pem(String label, Uint8List der) {
    final body = base64.encode(der);
    final buffer = StringBuffer('-----BEGIN $label-----\n');
    for (var offset = 0; offset < body.length; offset += 64) {
      final end = offset + 64 < body.length ? offset + 64 : body.length;
      buffer.writeln(body.substring(offset, end));
    }
    buffer.write('-----END $label-----\n');
    return buffer.toString();
  }

  static Uint8List derFromPem(String pem, String label) {
    final lines = pem
        .split('\n')
        .map((line) => line.trim())
        .where(
          (line) =>
              line.isNotEmpty &&
              line != '-----BEGIN $label-----' &&
              line != '-----END $label-----',
        )
        .join();
    return base64.decode(lines);
  }
}
