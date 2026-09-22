import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/pqc_tls_support.dart';
import 'package:quantum_bank_mobile/core/tls/tls_material_loader.dart';

class RecordingLoader implements TlsMaterialLoader {
  List<int>? loadedChain;

  @override
  void setTrustedCertificatesBytes(List<int> certificateBytes) {}

  @override
  void useCertificateChainBytes(List<int> chainBytes) {
    loadedChain = chainBytes;
  }

  @override
  void usePrivateKeyBytes(List<int> keyBytes) {}

  @override
  SecurityContext get context => SecurityContext(withTrustedRoots: false);
}

class RejectingLoader implements TlsMaterialLoader {
  RejectingLoader(this.error);

  final Object error;

  @override
  void setTrustedCertificatesBytes(List<int> certificateBytes) {}

  @override
  void useCertificateChainBytes(List<int> chainBytes) => throw error;

  @override
  void usePrivateKeyBytes(List<int> keyBytes) {}

  @override
  SecurityContext get context => SecurityContext(withTrustedRoots: false);
}

void main() {
  final rootAnchor = File('assets/local-ca/root-ca.crt').readAsBytesSync();

  test('reports support when the TLS stack loads an ML-DSA certificate', () {
    final loader = RecordingLoader();

    final status = PqcTlsSupport(loaderFactory: () => loader)
        .probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.supported, isTrue);
    expect(status.reason, isNull);
    expect(status.mode, TransportMode.postQuantum);
    expect(loader.loadedChain, equals(rootAnchor));
  });

  test('an unsupported stack selects the compatibility mode instead of failing closed', () {
    final status = PqcTlsSupport(
      loaderFactory: () => RejectingLoader(const TlsException('no ML-DSA')),
    ).probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.mode, TransportMode.compatibility);
  });

  test('the compatibility policy selects the compatibility mode with a reason', () {
    // Non-const on purpose so the constructor body is executed, not canonicalized.
    final status = PqcTransportStatus.compatibilityByPolicy(); // ignore: prefer_const_constructors

    expect(status.supported, isFalse);
    expect(status.mode, TransportMode.compatibility);
    expect(status.reason, contains('Política de transporte'));
    expect(status.reason, contains('envelope pós-quântico'));
  });

  test('trust anchors follow the transport mode', () {
    const pq = [1, 2, 3];
    const compat = [7, 8];

    expect(
      trustAnchorsFor(TransportMode.postQuantum, postQuantumRoot: pq, compatibilityRoot: compat),
      equals([1, 2, 3, 7, 8]),
    );
    expect(
      trustAnchorsFor(TransportMode.compatibility, postQuantumRoot: pq, compatibilityRoot: compat),
      equals([7, 8]),
    );
  });

  test('reports the TLS error when the stack rejects ML-DSA material', () {
    final status = PqcTlsSupport(
      loaderFactory: () => RejectingLoader(
        const TlsException('Failure in useCertificateChainBytes'),
      ),
    ).probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.supported, isFalse);
    expect(status.reason, contains('rejected ML-DSA certificate material'));
    expect(status.reason, contains('Failure in useCertificateChainBytes'));
  });

  test('prefers the OS error detail when present', () {
    final status = PqcTlsSupport(
      loaderFactory: () => RejectingLoader(
        const TlsException('boom', OSError('UNSUPPORTED_ALGORITHM', 1)),
      ),
    ).probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.supported, isFalse);
    expect(status.reason, contains('UNSUPPORTED_ALGORITHM'));
  });

  test('treats any other failure as unsupported', () {
    final status = PqcTlsSupport(
      loaderFactory: () => RejectingLoader(StateError('no tls')),
    ).probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.supported, isFalse);
    expect(status.reason, contains('cannot load ML-DSA certificate material'));
  });

  test('the platform probe never throws and yields a boolean verdict', () {
    // The bundled anchor is an ML-DSA-87 certificate; whether dart:io's
    // BoringSSL accepts it depends on the SDK. Either way the probe must
    // answer, never crash, so the app can fail closed with a reason.
    final status = const PqcTlsSupport().probe(mlDsaCertificateBytes: rootAnchor);

    expect(status.supported, isA<bool>());
    if (!status.supported) {
      expect(status.reason, isNotEmpty);
    }
  });
}
