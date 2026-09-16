import 'dart:io';

/// Thin seam over `dart:io`'s [SecurityContext] (a final class that cannot be
/// faked directly) so TLS material loading can be exercised in tests without
/// a platform stack that understands ML-DSA.
abstract interface class TlsMaterialLoader {
  void setTrustedCertificatesBytes(List<int> certificateBytes);

  void useCertificateChainBytes(List<int> chainBytes);

  void usePrivateKeyBytes(List<int> keyBytes);

  /// The configured context; only meaningful after the loaders succeeded.
  SecurityContext get context;
}

/// Production loader: explicit trust only (no platform roots), no permissive
/// callbacks; every call goes straight to the platform TLS stack.
class PlatformTlsMaterialLoader implements TlsMaterialLoader {
  PlatformTlsMaterialLoader() : context = SecurityContext(withTrustedRoots: false);

  @override
  final SecurityContext context;

  @override
  void setTrustedCertificatesBytes(List<int> certificateBytes) =>
      context.setTrustedCertificatesBytes(certificateBytes);

  @override
  void useCertificateChainBytes(List<int> chainBytes) =>
      context.useCertificateChainBytes(chainBytes);

  @override
  void usePrivateKeyBytes(List<int> keyBytes) =>
      context.usePrivateKeyBytes(keyBytes);
}
