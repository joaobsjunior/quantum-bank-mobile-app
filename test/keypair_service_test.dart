import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
import 'package:quantum_bank_mobile/core/tls/pqc_tls_support.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

void main() {
  final service = KeypairService();

  test('generates an ML-DSA-65 key pair by default with FIPS 204 sizes', () {
    final pair = service.generateMlDsaKeyPair();

    expect(pair.level, MlDsaLevel.mlDsa65);
    expect(pair.algorithm, 'ML-DSA-65');
    expect(pair.publicKey.length, DilithiumParams.mlDsa65.publicKeyBytes);
    expect(pair.privateKey.length, DilithiumParams.mlDsa65.secretKeyBytes);
    expect(pair.seed.length, 32);

    final message = Uint8List.fromList(utf8.encode('quantum-bank'));
    final signature = MlDsa.sign(pair.privateKey, message, pair.level.params);
    expect(MlDsa.verify(pair.publicKey, message, signature, pair.level.params), isTrue);
  });

  test('supports the ML-DSA-87 level accepted by the PKI', () {
    final pair = service.generateMlDsaKeyPair(level: MlDsaLevel.mlDsa87);

    expect(pair.algorithm, 'ML-DSA-87');
    expect(pair.publicKey.length, DilithiumParams.mlDsa87.publicKeyBytes);
    expect(MlDsaLevel.mlDsa87.oid, '2.16.840.1.101.3.4.3.19');
  });

  test('key pairs are unique and re-derivable from their seed', () {
    final first = service.generateMlDsaKeyPair();
    final second = service.generateMlDsaKeyPair();
    final (publicKey, privateKey) = MlDsa.generateKeyPairSeeded(
      DilithiumParams.mlDsa65,
      first.seed,
    );

    expect(first.publicKey, isNot(equals(second.publicKey)));
    expect(publicKey, equals(first.publicKey));
    expect(privateKey, equals(first.privateKey));
  });

  test('encodes the ML-DSA private key as seed-only PKCS#8 PEM (RFC 9881)', () {
    final pair = service.generateMlDsaKeyPair();

    final pem = service.encodePrivateKeyPem(pair);

    expect(pem, startsWith('-----BEGIN PRIVATE KEY-----\n'));
    expect(pem, endsWith('-----END PRIVATE KEY-----\n'));
    expect(pem.split('\n').every((line) => line.length <= 64), isTrue);

    final der = PqcAsn1.derFromPem(pem, PqcAsn1.pkcs8Label);
    final info = ASN1Parser(der).nextObject() as ASN1Sequence;
    expect((info.elements![0] as ASN1Integer).integer, BigInt.zero);
    final algorithm = info.elements![1] as ASN1Sequence;
    expect(
      (algorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      MlDsaLevel.mlDsa65.oid,
    );
    expect(algorithm.elements!.length, 1, reason: 'ML-DSA carries no parameters');
    final privateKey = info.elements![2] as ASN1OctetString;
    // ML-DSA-PrivateKey ::= CHOICE { seed [0] OCTET STRING (SIZE (32)), ... }:
    // context-specific primitive tag 0, 32 bytes, nothing else (the expanded
    // key is re-derived by every consumer; BoringSSL accepts only this form).
    final choice = privateKey.valueBytes!;
    expect(choice.length, 34);
    expect(choice[0], 0x80);
    expect(choice[1], 32);
    expect(choice.sublist(2), equals(pair.seed));
    expect(pair.transportMode, TransportMode.postQuantum);
    expect(pair.signatureAlgorithmIdentifier().elements!.length, 1);
  });

  test('generates an ECDSA P-256 identity for the compatibility chain', () {
    final pair = service.generateEcdsaP256KeyPair();
    final other = service.generateEcdsaP256KeyPair();

    expect(pair.algorithm, 'ECDSA-P256');
    expect(pair.transportMode, TransportMode.compatibility);
    expect(pair.uncompressedPoint.length, 65);
    expect(pair.uncompressedPoint[0], 0x04);
    expect(pair.uncompressedPoint, isNot(equals(other.uncompressedPoint)));

    final message = Uint8List.fromList(utf8.encode('quantum-bank'));
    final signature = pair.sign(message);
    expect(pair.verify(message, signature), isTrue);
    expect(pair.verify(Uint8List.fromList(utf8.encode('tampered')), signature), isFalse);
    expect(other.verify(message, signature), isFalse);
    // RFC 6979: deterministic signatures for the same key and message.
    expect(pair.sign(message), equals(signature));
  });

  test('encodes the ECDSA private key as PKCS#8 wrapping RFC 5915 ECPrivateKey', () {
    final pair = service.generateEcdsaP256KeyPair();

    final pem = service.encodePrivateKeyPem(pair);
    final der = PqcAsn1.derFromPem(pem, PqcAsn1.pkcs8Label);
    final info = ASN1Parser(der).nextObject() as ASN1Sequence;

    expect((info.elements![0] as ASN1Integer).integer, BigInt.zero);
    final algorithm = info.elements![1] as ASN1Sequence;
    expect(
      (algorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      PqcAsn1.ecPublicKeyOid,
    );
    expect(
      (algorithm.elements![1] as ASN1ObjectIdentifier).objectIdentifierAsString,
      PqcAsn1.secp256r1Oid,
    );
    final ecPrivateKey = ASN1Parser(
      (info.elements![2] as ASN1OctetString).valueBytes!,
    ).nextObject() as ASN1Sequence;
    expect((ecPrivateKey.elements![0] as ASN1Integer).integer, BigInt.one);
    final scalar = (ecPrivateKey.elements![1] as ASN1OctetString).valueBytes!;
    expect(scalar.length, 32);
    expect(scalar, equals(PqcAsn1.scalarBytes(pair.privateKey.d!)));
    expect(ecPrivateKey.elements![2].tag, 0xA0, reason: 'parameters [0]');
    expect(ecPrivateKey.elements![3].tag, 0xA1, reason: 'publicKey [1]');

    final spki = ASN1Parser(service.encodeSubjectPublicKeyInfo(pair)).nextObject()
        as ASN1Sequence;
    expect((spki.elements![1] as ASN1BitString).stringValues, equals(pair.uncompressedPoint));
  });

  test('scalar encoding is fixed width big-endian', () {
    expect(PqcAsn1.scalarBytes(BigInt.one), equals(Uint8List(32)..[31] = 1));
    expect(PqcAsn1.scalarBytes(BigInt.from(0x0102), width: 4), equals([0, 0, 1, 2]));
  });

  test('generateForTransport maps the mode to the key family', () {
    expect(service.generateForTransport(TransportMode.postQuantum), isA<MlDsaKeyPair>());
    expect(service.generateForTransport(TransportMode.compatibility), isA<EcdsaP256KeyPair>());
  });

  test('encodes the SubjectPublicKeyInfo with the ML-DSA algorithm identifier', () {
    final pair = service.generateMlDsaKeyPair();

    final spki = ASN1Parser(service.encodeSubjectPublicKeyInfo(pair)).nextObject()
        as ASN1Sequence;

    final algorithm = spki.elements![0] as ASN1Sequence;
    expect(
      (algorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      MlDsaLevel.mlDsa65.oid,
    );
    final publicKey = spki.elements![1] as ASN1BitString;
    expect(publicKey.stringValues, equals(pair.publicKey));
  });

  test('PEM helpers round-trip arbitrary DER', () {
    final der = Uint8List.fromList(List<int>.generate(100, (i) => i));

    final pem = PqcAsn1.pem('CERTIFICATE REQUEST', der);

    expect(PqcAsn1.derFromPem(pem, PqcAsn1.csrLabel), equals(der));
    expect(PqcAsn1.derFromPem('  $pem  ', PqcAsn1.csrLabel), equals(der));
  });
}
