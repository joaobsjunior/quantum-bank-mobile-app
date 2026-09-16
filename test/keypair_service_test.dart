import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
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

  test('encodes the private key as PKCS#8 PEM carrying seed and expanded key', () {
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
    final both = ASN1Parser(privateKey.valueBytes!).nextObject() as ASN1Sequence;
    expect((both.elements![0] as ASN1OctetString).valueBytes, equals(pair.seed));
    expect((both.elements![1] as ASN1OctetString).valueBytes, equals(pair.privateKey));
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
