import 'dart:io';

import 'tls_material_loader.dart';

/// Result of probing whether the platform TLS stack can use post-quantum
/// (ML-DSA) certificate material.
class PqcTransportStatus {
  const PqcTransportStatus.supported()
    : supported = true,
      reason = null;

  const PqcTransportStatus.unsupported(String this.reason) : supported = false;

  final bool supported;
  final String? reason;
}

/// Quantum Bank transport is post-quantum only: every gateway and issuer
/// listener authenticates with ML-DSA certificates and negotiates the
/// X25519MLKEM768 group. `dart:io` delegates TLS to the platform BoringSSL
/// build, which (as of Dart 3.11) rejects ML-DSA keys and certificates with
/// `UNSUPPORTED_ALGORITHM`. The app probes that capability at startup with the
/// bundled ML-DSA root anchor and fails closed, so it never silently falls back
/// to a classical handshake or reports a certificate as usable when the socket
/// layer cannot present it.
class PqcTlsSupport {
  const PqcTlsSupport({TlsMaterialLoader Function()? loaderFactory})
    : _loaderFactory = loaderFactory ?? PlatformTlsMaterialLoader.new;

  final TlsMaterialLoader Function() _loaderFactory;

  /// Returns [PqcTransportStatus.supported] only when the TLS stack accepts an
  /// ML-DSA certificate as its own certificate chain, which is the operation a
  /// post-quantum mTLS client needs.
  PqcTransportStatus probe({required List<int> mlDsaCertificateBytes}) {
    try {
      _loaderFactory().useCertificateChainBytes(mlDsaCertificateBytes);
      return const PqcTransportStatus.supported();
    } on TlsException catch (error) {
      return PqcTransportStatus.unsupported(
        'platform TLS stack rejected ML-DSA certificate material: '
        '${error.osError?.message ?? error.message}',
      );
    } catch (error) {
      return PqcTransportStatus.unsupported(
        'platform TLS stack cannot load ML-DSA certificate material: $error',
      );
    }
  }
}
