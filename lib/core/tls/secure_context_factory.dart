import 'dart:io';

import 'tls_material_loader.dart';

class TlsConfigurationException implements Exception {
  const TlsConfigurationException(this.message);

  final String message;

  @override
  String toString() => 'TlsConfigurationException: $message';
}

/// Builds the mTLS [SecurityContext] for banking calls: explicit ML-DSA-87
/// trust anchor, the enrolled ML-DSA-65 client certificate chain and its
/// PKCS#8 private key. No permissive callback exists; any material the TLS
/// stack cannot load (including a platform stack without ML-DSA support) is a
/// hard failure.
class SecureContextFactory {
  const SecureContextFactory({TlsMaterialLoader Function()? loaderFactory})
    : _loaderFactory = loaderFactory ?? PlatformTlsMaterialLoader.new;

  final TlsMaterialLoader Function() _loaderFactory;

  SecurityContext build({
    required List<int> trustedCaBytes,
    required List<int> certificateChainBytes,
    required List<int> privateKeyBytes,
  }) {
    try {
      final loader = _loaderFactory()
        ..setTrustedCertificatesBytes(trustedCaBytes)
        ..useCertificateChainBytes(certificateChainBytes)
        ..usePrivateKeyBytes(privateKeyBytes);
      return loader.context;
    } catch (_) {
      throw const TlsConfigurationException(
        'invalid mTLS certificate material or platform TLS stack without ML-DSA support',
      );
    }
  }
}
