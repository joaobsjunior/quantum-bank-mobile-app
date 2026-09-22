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

/// ASN.1 / PEM helpers for the two device key families: ML-DSA (algorithm
/// identifiers carry no parameters, the OID alone selects the parameter set)
/// and ECDSA P-256 for the compatibility chain (RFC 5480 / RFC 5915).
abstract final class PqcAsn1 {
  static const String pkcs8Label = 'PRIVATE KEY';
  static const String csrLabel = 'CERTIFICATE REQUEST';

  /// `id-ecPublicKey` (RFC 5480).
  static const String ecPublicKeyOid = '1.2.840.10045.2.1';

  /// `secp256r1` / P-256 named curve, the only classical curve the PKI issues.
  static const String secp256r1Oid = '1.2.840.10045.3.1.7';

  /// `ecdsa-with-SHA256` (RFC 5758).
  static const String ecdsaWithSha256Oid = '1.2.840.10045.4.3.2';

  /// Canonical family name of the P-256 identity, shared with the PKI scripts.
  static const String ecdsaP256AlgorithmName = 'ECDSA-P256';

  /// `id-alg-ml-kem-768` (NIST CSOR arc), the envelope KEM.
  static const String mlKem768Oid = '2.16.840.1.101.3.4.4.2';

  /// `id-X25519` (RFC 8410).
  static const String x25519Oid = '1.3.101.110';

  static const int _contextSpecificPrimitive0 = 0x80;
  static const int _contextSpecificConstructed0 = 0xA0;
  static const int _contextSpecificConstructed1 = 0xA1;

  static ASN1Sequence algorithmIdentifier(MlDsaLevel level) => ASN1Sequence(
    elements: [ASN1ObjectIdentifier.fromIdentifierString(level.oid)],
  );

  /// `SubjectPublicKeyInfo { algorithm id-ml-dsa-*, subjectPublicKey BIT STRING }`.
  static ASN1Sequence subjectPublicKeyInfoAsn1(
    MlDsaLevel level,
    Uint8List publicKey,
  ) => ASN1Sequence(
    elements: [
      algorithmIdentifier(level),
      ASN1BitString(stringValues: publicKey),
    ],
  );

  /// PKCS#8 `PrivateKeyInfo` with the `seed [0] OCTET STRING` choice of
  /// `ML-DSA-PrivateKey` (RFC 9881). This is the only representation
  /// BoringSSL parses; OpenSSL >= 3.5 and BouncyCastle accept it and expand
  /// the key from the seed, so it is also the most interoperable one.
  static Uint8List privateKeyInfo(MlDsaLevel level, {required Uint8List seed}) {
    final seedChoice = ASN1OctetString(
      octets: seed,
      tag: _contextSpecificPrimitive0,
    );
    return ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.zero),
        algorithmIdentifier(level),
        ASN1OctetString(octets: seedChoice.encode()),
      ],
    ).encode();
  }

  /// PKCS#8 `PrivateKeyInfo` of an ML-KEM-768 decapsulation key in the
  /// `seed [0] OCTET STRING` form (the 64-byte `d || z` of FIPS 203), the
  /// representation OpenSSL >= 3.5 and BouncyCastle import. Used only by the
  /// interop tooling: the app never holds a KEM private key.
  static Uint8List mlKemPrivateKeyInfo(Uint8List seed) {
    final seedChoice = ASN1OctetString(octets: seed, tag: _contextSpecificPrimitive0);
    return ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.zero),
        ASN1Sequence(
          elements: [ASN1ObjectIdentifier.fromIdentifierString(mlKem768Oid)],
        ),
        ASN1OctetString(octets: seedChoice.encode()),
      ],
    ).encode();
  }

  /// PKCS#8 `PrivateKeyInfo` of an X25519 private key (RFC 8410: the
  /// `privateKey` OCTET STRING wraps a `CurvePrivateKey ::= OCTET STRING`).
  static Uint8List x25519PrivateKeyInfo(Uint8List scalar) => ASN1Sequence(
    elements: [
      ASN1Integer(BigInt.zero),
      ASN1Sequence(
        elements: [ASN1ObjectIdentifier.fromIdentifierString(x25519Oid)],
      ),
      ASN1OctetString(octets: ASN1OctetString(octets: scalar).encode()),
    ],
  ).encode();

  /// `SubjectPublicKeyInfo` of an X25519 public key (RFC 8410).
  static Uint8List x25519SubjectPublicKeyInfo(Uint8List publicKey) =>
      ASN1Sequence(
        elements: [
          ASN1Sequence(
            elements: [ASN1ObjectIdentifier.fromIdentifierString(x25519Oid)],
          ),
          ASN1BitString(stringValues: publicKey),
        ],
      ).encode();

  /// `AlgorithmIdentifier { id-ecPublicKey, secp256r1 }`.
  static ASN1Sequence ecAlgorithmIdentifier() => ASN1Sequence(
    elements: [
      ASN1ObjectIdentifier.fromIdentifierString(ecPublicKeyOid),
      ASN1ObjectIdentifier.fromIdentifierString(secp256r1Oid),
    ],
  );

  /// `AlgorithmIdentifier { ecdsa-with-SHA256 }` (parameters absent).
  static ASN1Sequence ecdsaWithSha256AlgorithmIdentifier() => ASN1Sequence(
    elements: [ASN1ObjectIdentifier.fromIdentifierString(ecdsaWithSha256Oid)],
  );

  /// `SubjectPublicKeyInfo` for an uncompressed P-256 point (`04 || X || Y`).
  static ASN1Sequence ecSubjectPublicKeyInfoAsn1(Uint8List uncompressedPoint) =>
      ASN1Sequence(
        elements: [
          ecAlgorithmIdentifier(),
          ASN1BitString(stringValues: uncompressedPoint),
        ],
      );

  /// PKCS#8 `PrivateKeyInfo` wrapping an RFC 5915 `ECPrivateKey { version 1,
  /// privateKey, parameters [0] secp256r1, publicKey [1] BIT STRING }`, the
  /// form every TLS stack (BoringSSL, OpenSSL, BouncyCastle) loads.
  static Uint8List ecPrivateKeyInfo({
    required Uint8List scalar,
    required Uint8List uncompressedPoint,
  }) {
    final ecPrivateKey = ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.one),
        ASN1OctetString(octets: scalar),
        ASN1Sequence(
          elements: [ASN1ObjectIdentifier.fromIdentifierString(secp256r1Oid)],
          tag: _contextSpecificConstructed0,
        ),
        ASN1Sequence(
          elements: [ASN1BitString(stringValues: uncompressedPoint)],
          tag: _contextSpecificConstructed1,
        ),
      ],
    );
    return ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.zero),
        ecAlgorithmIdentifier(),
        ASN1OctetString(octets: ecPrivateKey.encode()),
      ],
    ).encode();
  }

  /// DER `Ecdsa-Sig-Value { r INTEGER, s INTEGER }` (RFC 5480).
  static Uint8List ecdsaSignature(BigInt r, BigInt s) =>
      ASN1Sequence(elements: [ASN1Integer(r), ASN1Integer(s)]).encode();

  /// Fixed-width big-endian encoding of a P-256 scalar.
  static Uint8List scalarBytes(BigInt value, {int width = 32}) {
    final bytes = Uint8List(width);
    var remaining = value;
    for (var i = width - 1; i >= 0; i--) {
      bytes[i] = (remaining & BigInt.from(0xff)).toInt();
      remaining = remaining >> 8;
    }
    return bytes;
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
