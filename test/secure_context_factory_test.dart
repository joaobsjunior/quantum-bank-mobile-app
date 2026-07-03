import 'dart:convert';
import 'dart:io';

import 'package:basic_utils/basic_utils.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/secure_context_factory.dart';
import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

void main() {
  test('builds a security context from valid mTLS material', () {
    final keyService = KeypairService();
    final pair = keyService.generateRsaKeyPair(bitLength: 2048);
    final csrPem = CsrService().generatePem(
      input: const CsrInput(
        oauth2Subject: 'alice@quantumbank.local',
        appInstanceId: 'app-local-001',
        deviceId: 'device-local-001',
        certificateProfile: 'quantum-bank-mobile-client-v1',
        environment: 'local',
      ),
      keyPair: pair,
    );
    final certPem = X509Utils.generateSelfSignedCertificate(pair.privateKey, csrPem, 365);
    final keyPem = keyService.encodePrivateKeyPem(pair.privateKey);

    final context = SecureContextFactory().build(
      trustedCaBytes: File('assets/local-ca/root-ca.crt').readAsBytesSync(),
      certificateChainBytes: utf8.encode(certPem),
      privateKeyBytes: utf8.encode(keyPem),
    );

    expect(context, isA<SecurityContext>());
  });

  test('TlsConfigurationException describes itself', () {
    expect(
      const TlsConfigurationException('bad material').toString(),
      equals('TlsConfigurationException: bad material'),
    );
  });

  test('factory is importable and rejects invalid certificate material', () {
    final factory = SecureContextFactory();

    expect(
      () => factory.build(
        trustedCaBytes: const <int>[1, 2, 3],
        certificateChainBytes: const <int>[4, 5, 6],
        privateKeyBytes: const <int>[7, 8, 9],
      ),
      throwsA(isA<TlsConfigurationException>()),
    );
  });

  test(
    'source uses explicit trust and never exposes badCertificateCallback',
    () {
      final source = File(
        'lib/core/tls/secure_context_factory.dart',
      ).readAsStringSync();

      expect(source, contains('SecurityContext(withTrustedRoots: false)'));
      expect(source, contains('setTrustedCertificatesBytes'));
      expect(source, contains('useCertificateChainBytes'));
      expect(source, contains('usePrivateKeyBytes'));
      expect(source, isNot(contains('badCertificateCallback')));
    },
  );
}
