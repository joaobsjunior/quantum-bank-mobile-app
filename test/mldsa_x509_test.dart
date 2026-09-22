import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/mldsa_x509.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';

String fixture(String name) => File('test/fixtures/envelope/$name').readAsStringSync();

/// Inside the validity window of the fixture chain (issued 2026-09-18 for 90 days).
final now = DateTime.utc(2026, 10, 1);

int _indexOf(List<int> haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return i;
    }
  }
  return -1;
}

void main() {
  final root = MlDsaCertificate.fromPem(fixture('root-ca.crt'));
  final issuing = MlDsaCertificate.fromPem(fixture('issuing-ca.crt'));
  final leaf = MlDsaCertificate.fromPem(fixture('backend-server.crt'));

  test('parses the PKI-issued ML-DSA certificates', () {
    expect(root.isCa, isTrue);
    expect(root.publicKeyLevel, MlDsaLevel.mlDsa87);
    expect(root.commonName, equals('QuantumBank Local Root CA'));
    expect(issuing.isCa, isTrue);
    expect(issuing.signatureLevel, MlDsaLevel.mlDsa87);
    expect(leaf.isCa, isFalse);
    expect(leaf.commonName, equals('backend'));
    expect(leaf.publicKeyLevel, MlDsaLevel.mlDsa65);
    expect(leaf.publicKey, hasLength(1952));
    expect(leaf.signatureLevel, MlDsaLevel.mlDsa87);
    expect(leaf.signature, hasLength(4627));
    expect(leaf.notBefore.isBefore(leaf.notAfter), isTrue);
    expect(leaf.isValidAt(now), isTrue);
    expect(leaf.isValidAt(DateTime.utc(2030)), isFalse);
    expect(leaf.isValidAt(DateTime.utc(2020)), isFalse);
  });

  test('verifies the chain leaf → issuing → root with ML-DSA signatures', () {
    final verified = MlDsaChainVerifier(trustAnchor: root).verify([leaf, issuing], now: now);

    expect(identical(verified, leaf), isTrue);
    expect(leaf.issuedBy(issuing), isTrue);
    expect(leaf.isSignedBy(issuing), isTrue);
    expect(issuing.isSignedBy(root), isTrue);
    expect(leaf.isSignedBy(root), isFalse);
  });

  test('rejects broken chains', () {
    final verifier = MlDsaChainVerifier(trustAnchor: root);
    void expectFails(List<MlDsaCertificate> chain, String fragment, {DateTime? at, MlDsaChainVerifier? with_}) {
      expect(
        () => (with_ ?? verifier).verify(chain, now: at ?? now),
        throwsA(
          isA<CertificateVerificationException>().having((e) => e.toString(), 'message', contains(fragment)),
        ),
      );
    }

    expectFails([], 'empty certificate chain');
    expectFails([leaf], 'not issued by');
    expectFails([issuing, leaf], 'is not a CA');
    expectFails([leaf, issuing], 'outside its validity window', at: DateTime.utc(2030));
    expectFails([leaf, issuing], 'trust anchor is not a CA', with_: MlDsaChainVerifier(trustAnchor: leaf));

    final tampered = MlDsaCertificate(
      tbsCertificate: leaf.tbsCertificate,
      issuer: leaf.issuer,
      subject: leaf.subject,
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
      publicKeyLevel: leaf.publicKeyLevel,
      publicKey: leaf.publicKey,
      signatureLevel: leaf.signatureLevel,
      signature: Uint8List.fromList(leaf.signature)..[10] ^= 0xff,
      isCa: false,
      commonName: leaf.commonName,
    );
    expectFails([tampered, issuing], 'does not verify');
  });

  test('rejects certificates that are not ML-DSA or not DER', () {
    expect(
      () => MlDsaCertificate.fromPem(fixture('root-ca-compat.crt')),
      throwsA(
        isA<CertificateVerificationException>()
            .having((e) => e.message, 'message', contains('not ML-DSA-65/87')),
      ),
    );
    expect(
      () => MlDsaCertificate.fromDer(Uint8List.fromList([0x30, 0x03, 0x02, 0x01, 0x01])),
      throwsA(
        isA<CertificateVerificationException>().having((e) => e.message, 'message', contains('malformed')),
      ),
    );
    expect(const CertificateVerificationException('x').toString(), contains('x'));
  });

  test('accepts a PrintableString common name and rejects a malformed validity time', () {
    final der = PqcAsn1.derFromPem(fixture('backend-server.crt'), 'CERTIFICATE');
    // CN=backend encoded as UTF8String: 06 03 55 04 03 0c 07 'backend'.
    final cnPattern = [0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, ...'backend'.codeUnits];
    final cnOffset = _indexOf(der, cnPattern);
    expect(cnOffset, greaterThan(0));
    final printable = Uint8List.fromList(der)..[cnOffset + 5] = 0x13;
    expect(MlDsaCertificate.fromDer(printable).commonName, equals('backend'));

    // Validity: 30 1e 17 0d <13 bytes> 17 0d <13 bytes>; retag notBefore as OCTET STRING.
    final validityOffset = _indexOf(der, [0x30, 0x1e, 0x17, 0x0d]);
    expect(validityOffset, greaterThan(0));
    final broken = Uint8List.fromList(der)..[validityOffset + 2] = 0x04;
    expect(
      () => MlDsaCertificate.fromDer(broken),
      throwsA(
        isA<CertificateVerificationException>().having((e) => e.message, 'message', contains('invalid validity time')),
      ),
    );
  });

  test('reads both X.509 time encodings', () {
    expect(MlDsaCertificate.timeOf(ASN1UtcTime(DateTime.utc(2026, 9, 19))), equals(DateTime.utc(2026, 9, 19)));
    expect(MlDsaCertificate.timeOf(ASN1GeneralizedTime(DateTime.utc(2051, 1, 1))), equals(DateTime.utc(2051, 1, 1)));
    expect(() => MlDsaCertificate.timeOf(ASN1Integer(BigInt.one)), throwsA(isA<CertificateVerificationException>()));
  });

  test('exposes the DER helpers used for fixtures', () {
    final der = PqcAsn1.derFromPem(fixture('backend-server.crt'), 'CERTIFICATE');
    expect(MlDsaCertificate.fromDer(der).commonName, equals('backend'));
  });
}
