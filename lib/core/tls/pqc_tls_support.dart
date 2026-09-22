import 'dart:io';

import 'tls_material_loader.dart';

/// Which of the two PKI chains the device transport can use.
///
/// Every Quantum Bank listener the app talks to serves a dual identity: the
/// ML-DSA-65 certificate to clients whose TLS stack offers ML-DSA signature
/// schemes, the ECDSA P-256 compatibility certificate to every other client.
/// The device identity follows the same rule: an ML-DSA-65 key pair when the
/// platform can present it, an ECDSA P-256 key pair otherwise.
enum TransportMode {
  /// ML-DSA-65 device identity, ML-DSA-87 root anchor, ML-KEM hybrid key
  /// exchange: the platform TLS stack loads ML-DSA material.
  postQuantum,

  /// ECDSA P-256 device identity under the ECDSA compatibility chain. Used
  /// while `dart:io` delegates TLS to a BoringSSL build that does not accept
  /// ML-DSA signature schemes by default (Dart 3.11 rejects ML-DSA keys and
  /// certificates outright; Dart 3.13 parses them but its BoringSSL still
  /// does not offer ML-DSA in `signature_algorithms`).
  compatibility,
}

/// Result of probing whether the platform TLS stack can use post-quantum
/// (ML-DSA) certificate material.
class PqcTransportStatus {
  const PqcTransportStatus.supported()
    : supported = true,
      reason = null;

  const PqcTransportStatus.unsupported(String this.reason) : supported = false;

  /// Compatibility transport selected by the `PQC_TRANSPORT_POLICY` build
  /// setting (the default): the post-quantum guarantees of the app edge come
  /// from the application-layer envelope, not from the TLS stack.
  const PqcTransportStatus.compatibilityByPolicy()
    : supported = false,
      reason =
          'Política de transporte: compatibilidade (ECDSA P-256 no TLS); '
          'o envelope pós-quântico da camada de aplicação protege o tráfego.';

  /// Whether ML-DSA material is usable by the platform TLS stack.
  final bool supported;

  /// Platform detail when [supported] is false.
  final String? reason;

  /// The transport mode the app runs in; never a fail-closed state, because
  /// the compatibility chain is a first-class, PKI-issued identity.
  TransportMode get mode =>
      supported ? TransportMode.postQuantum : TransportMode.compatibility;
}

/// Trust anchors for [mode]: the compatibility root is always trusted because
/// a dual-identity listener may serve the ECDSA chain to any client that
/// advertises ECDSA schemes; the ML-DSA root is added only when the platform
/// can load it (loading it on an unsupported stack throws).
List<int> trustAnchorsFor(
  TransportMode mode, {
  required List<int> postQuantumRoot,
  required List<int> compatibilityRoot,
}) => switch (mode) {
  TransportMode.postQuantum => [...postQuantumRoot, ...compatibilityRoot],
  TransportMode.compatibility => List<int>.of(compatibilityRoot),
};

/// Probes, at startup, whether `dart:io` can present ML-DSA material. The
/// verdict selects the [TransportMode]: the app never silently degrades a
/// post-quantum-capable device, and never blocks a device that can only use
/// the compatibility chain.
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
