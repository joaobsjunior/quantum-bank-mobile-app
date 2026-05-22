import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/secure_context_factory.dart';

void main() {
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
