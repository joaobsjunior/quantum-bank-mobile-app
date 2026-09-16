import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/secure_context_factory.dart';
import 'package:quantum_bank_mobile/core/tls/tls_material_loader.dart';

class RecordingLoader implements TlsMaterialLoader {
  List<int>? trusted;
  List<int>? chain;
  List<int>? key;

  @override
  final SecurityContext context = SecurityContext(withTrustedRoots: false);

  @override
  void setTrustedCertificatesBytes(List<int> certificateBytes) {
    trusted = certificateBytes;
  }

  @override
  void useCertificateChainBytes(List<int> chainBytes) {
    chain = chainBytes;
  }

  @override
  void usePrivateKeyBytes(List<int> keyBytes) {
    key = keyBytes;
  }
}

void main() {
  test('builds a security context with explicit trust and client material', () {
    final recording = RecordingLoader();
    final trusted = File('assets/local-ca/root-ca.crt').readAsBytesSync();

    final context = SecureContextFactory(loaderFactory: () => recording).build(
      trustedCaBytes: trusted,
      certificateChainBytes: const <int>[4, 5, 6],
      privateKeyBytes: const <int>[7, 8, 9],
    );

    expect(context, same(recording.context));
    expect(recording.trusted, equals(trusted));
    expect(recording.chain, equals(const <int>[4, 5, 6]));
    expect(recording.key, equals(const <int>[7, 8, 9]));
  });

  test('TlsConfigurationException describes itself', () {
    expect(
      const TlsConfigurationException('bad material').toString(),
      equals('TlsConfigurationException: bad material'),
    );
  });

  test('platform factory fails closed on invalid certificate material', () {
    const factory = SecureContextFactory();

    expect(
      () => factory.build(
        trustedCaBytes: const <int>[1, 2, 3],
        certificateChainBytes: const <int>[4, 5, 6],
        privateKeyBytes: const <int>[7, 8, 9],
      ),
      throwsA(
        isA<TlsConfigurationException>().having(
          (e) => e.message,
          'message',
          contains('ML-DSA'),
        ),
      ),
    );
  });

  test(
    'source uses explicit trust and never exposes badCertificateCallback',
    () {
      final source = File(
        'lib/core/tls/secure_context_factory.dart',
      ).readAsStringSync();

      final loader = File(
        'lib/core/tls/tls_material_loader.dart',
      ).readAsStringSync();

      expect(loader, contains('SecurityContext(withTrustedRoots: false)'));
      expect(loader, isNot(contains('badCertificateCallback')));
      expect(source, contains('setTrustedCertificatesBytes'));
      expect(source, contains('useCertificateChainBytes'));
      expect(source, contains('usePrivateKeyBytes'));
      expect(source, isNot(contains('badCertificateCallback')));
    },
  );
}
