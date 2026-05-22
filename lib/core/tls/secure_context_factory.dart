import 'dart:io';

class TlsConfigurationException implements Exception {
  const TlsConfigurationException(this.message);

  final String message;

  @override
  String toString() => 'TlsConfigurationException: $message';
}

class SecureContextFactory {
  SecurityContext build({
    required List<int> trustedCaBytes,
    required List<int> certificateChainBytes,
    required List<int> privateKeyBytes,
  }) {
    try {
      final context = SecurityContext(withTrustedRoots: false)
        ..setTrustedCertificatesBytes(trustedCaBytes)
        ..useCertificateChainBytes(certificateChainBytes)
        ..usePrivateKeyBytes(privateKeyBytes);
      return context;
    } catch (_) {
      throw const TlsConfigurationException(
        'invalid mTLS certificate material',
      );
    }
  }
}
