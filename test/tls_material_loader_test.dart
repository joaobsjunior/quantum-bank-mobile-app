import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/tls_material_loader.dart';

void main() {
  test('platform loader forwards every call to a strict SecurityContext', () {
    final loader = PlatformTlsMaterialLoader();

    expect(loader.context, isA<SecurityContext>());
    // Garbage is refused by the platform stack; no permissive path exists.
    expect(
      () => loader.setTrustedCertificatesBytes(const <int>[1, 2, 3]),
      throwsA(isA<TlsException>()),
    );
    expect(
      () => loader.useCertificateChainBytes(const <int>[4, 5, 6]),
      throwsA(isA<TlsException>()),
    );
    expect(
      () => loader.usePrivateKeyBytes(const <int>[7, 8, 9]),
      throwsA(isA<ArgumentError>()),
    );
  });
}
