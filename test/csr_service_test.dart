import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

const input = CsrInput(
  oauth2Subject: 'alice@quantumbank.local',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
);

void main() {
  test('CSR input maps identity fields to the subject and SAN URIs', () {
    expect(input.distinguishedName, {
      'CN': 'alice@quantumbank.local',
      'O': 'Quantum Bank',
      'OU': 'quantum-bank-mobile-client-v1',
      'ST': 'app-local-001',
      'SN': 'device-local-001',
      'L': 'local',
    });
    expect(input.subjectAlternativeNames, [
      'urn:quantum-bank:subject:alice@quantumbank.local',
      'urn:quantum-bank:app-instance:app-local-001',
      'urn:quantum-bank:device:device-local-001',
      'urn:quantum-bank:environment:local',
    ]);
  });

  test('generates a PKCS#10 request signed and keyed with ECDSA P-256 in compatibility mode', () {
    final keyPair = KeypairService().generateEcdsaP256KeyPair();
    final service = CsrService();

    final csrPem = service.generatePem(input: input, keyPair: keyPair);
    final csr = ASN1Parser(PqcAsn1.derFromPem(csrPem, PqcAsn1.csrLabel)).nextObject()
        as ASN1Sequence;
    final info = csr.elements![0] as ASN1Sequence;
    final signatureAlgorithm = csr.elements![1] as ASN1Sequence;
    final signature = csr.elements![2] as ASN1BitString;

    expect(
      (signatureAlgorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      PqcAsn1.ecdsaWithSha256Oid,
    );
    expect(signatureAlgorithm.elements!.length, 1, reason: 'ecdsa-with-SHA256 has no parameters');
    // Proof of possession: DER Ecdsa-Sig-Value over the DER CertificationRequestInfo.
    expect(
      keyPair.verify(info.encode(), Uint8List.fromList(signature.stringValues!)),
      isTrue,
    );
    final spki = info.elements![2] as ASN1Sequence;
    final spkiAlgorithm = spki.elements![0] as ASN1Sequence;
    expect(
      (spkiAlgorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      PqcAsn1.ecPublicKeyOid,
    );
    expect(
      (spkiAlgorithm.elements![1] as ASN1ObjectIdentifier).objectIdentifierAsString,
      PqcAsn1.secp256r1Oid,
    );
    expect((spki.elements![1] as ASN1BitString).stringValues, equals(keyPair.uncompressedPoint));
  });

  test('generates a PKCS#10 request signed and keyed with ML-DSA-65', () {
    final keyPair = KeypairService().generateMlDsaKeyPair();
    final service = CsrService();

    final csrPem = service.generatePem(input: input, keyPair: keyPair);

    expect(csrPem, startsWith('-----BEGIN CERTIFICATE REQUEST-----\n'));
    expect(csrPem, endsWith('-----END CERTIFICATE REQUEST-----\n'));
    expect(csrPem, isNot(contains('PRIVATE KEY')));

    final csr = ASN1Parser(PqcAsn1.derFromPem(csrPem, PqcAsn1.csrLabel)).nextObject()
        as ASN1Sequence;
    expect(csr.elements!.length, 3);
    final info = csr.elements![0] as ASN1Sequence;
    final signatureAlgorithm = csr.elements![1] as ASN1Sequence;
    final signature = csr.elements![2] as ASN1BitString;

    expect(
      (signatureAlgorithm.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      MlDsaLevel.mlDsa65.oid,
    );
    expect(signature.stringValues!.length, DilithiumParams.mlDsa65.signatureBytes);

    // Proof of possession: the pure ML-DSA signature covers the DER
    // CertificationRequestInfo exactly as OpenSSL and BouncyCastle verify it.
    expect(
      MlDsa.verify(
        keyPair.publicKey,
        info.encode(),
        Uint8List.fromList(signature.stringValues!),
        DilithiumParams.mlDsa65,
      ),
      isTrue,
    );

    expect((info.elements![0] as ASN1Integer).integer, BigInt.zero);
    final subject = info.elements![1] as ASN1Sequence;
    final rdns = subject.elements!.map((set) {
      final attribute = ((set as ASN1Set).elements!.single as ASN1Sequence).elements!;
      return (
        (attribute[0] as ASN1ObjectIdentifier).objectIdentifierAsString,
        (attribute[1] as ASN1UTF8String).utf8StringValue,
      );
    }).toList();
    expect(rdns, [
      ('2.5.4.3', 'alice@quantumbank.local'),
      ('2.5.4.10', 'Quantum Bank'),
      ('2.5.4.11', 'quantum-bank-mobile-client-v1'),
      ('2.5.4.8', 'app-local-001'),
      ('2.5.4.4', 'device-local-001'),
      ('2.5.4.7', 'local'),
    ]);

    final spki = info.elements![2] as ASN1Sequence;
    expect((spki.elements![1] as ASN1BitString).stringValues, equals(keyPair.publicKey));

    // attributes [0] IMPLICIT SET OF Attribute: the parser yields a generic
    // tagged object, so decode its content explicitly.
    final attributes = info.elements![3];
    expect(attributes.tag, 0xA0);
    final extensionRequest =
        ASN1Parser(attributes.valueBytes!).nextObject() as ASN1Sequence;
    expect(
      (extensionRequest.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      '1.2.840.113549.1.9.14',
    );
    final extensions =
        (extensionRequest.elements![1] as ASN1Set).elements!.single as ASN1Sequence;
    final subjectAltName = extensions.elements!.single as ASN1Sequence;
    expect(
      (subjectAltName.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString,
      '2.5.29.17',
    );
    final generalNames = ASN1Parser(
      (subjectAltName.elements![1] as ASN1OctetString).valueBytes!,
    ).nextObject() as ASN1Sequence;
    final uris = generalNames.elements!
        .map((name) => utf8.decode(name.valueBytes!))
        .toList();
    expect(uris, input.subjectAlternativeNames);
    expect(generalNames.elements!.every((name) => name.tag == 0x86), isTrue);
  });

  test('hedged signing produces distinct but valid signatures', () {
    final keyPair = KeypairService().generateMlDsaKeyPair();
    final service = CsrService();

    final first = service.generateDer(input: input, keyPair: keyPair);
    final second = service.generateDer(input: input, keyPair: keyPair);

    expect(first, isNot(equals(second)));
    for (final der in [first, second]) {
      final csr = ASN1Parser(der).nextObject() as ASN1Sequence;
      expect(
        MlDsa.verify(
          keyPair.publicKey,
          (csr.elements![0] as ASN1Sequence).encode(),
          Uint8List.fromList((csr.elements![2] as ASN1BitString).stringValues!),
          DilithiumParams.mlDsa65,
        ),
        isTrue,
      );
    }
  });
}
