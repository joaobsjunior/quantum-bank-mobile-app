/// Thrown when the runtime configuration would weaken the secure path (for
/// example a plaintext issuer or gateway origin).
class InsecureRuntimeConfigException implements Exception {
  const InsecureRuntimeConfigException(this.message);

  final String message;

  @override
  String toString() => 'InsecureRuntimeConfigException: $message';
}

/// How the device transport mode is chosen (feature 012, story 5).
enum TransportPolicy {
  /// ECDSA P-256 transport identity under the compatibility chain; the
  /// post-quantum protection of the app edge is the application envelope.
  compatibility,

  /// Feature 011 behaviour: probe whether `dart:io` loads ML-DSA material and
  /// enroll an ML-DSA-65 transport identity when it does. Opt-in, because a
  /// stack that loads ML-DSA certificates but cannot sign the handshake would
  /// otherwise lock the device out.
  probe;

  static TransportPolicy parse(String value) => switch (value) {
    'probe' => TransportPolicy.probe,
    'compatibility' || '' => TransportPolicy.compatibility,
    _ => throw InsecureRuntimeConfigException(
      'PQC_TRANSPORT_POLICY must be compatibility or probe, got $value',
    ),
  };
}

class RuntimeConfig {
  RuntimeConfig({
    required this.keycloakTokenUrl,
    required this.keycloakClientId,
    required this.keycloakClientSecret,
    required this.localUsername,
    required this.localPassword,
    required this.gatewayBootstrapBaseUrl,
    required this.gatewayBaseUrl,
    required this.trustedCaAsset,
    required this.compatTrustedCaAsset,
    required this.appInstanceId,
    required this.deviceId,
    required this.certificateProfile,
    required this.environment,
    this.transportPolicy = TransportPolicy.compatibility,
    this.envelopeSignerCommonName = 'backend',
  }) {
    // Fail closed: credentials, tokens and certificates only ever travel over
    // TLS verified against the bundled trust anchor.
    for (final origin in [keycloakTokenUrl, gatewayBootstrapBaseUrl, gatewayBaseUrl]) {
      if (origin.scheme != 'https') {
        throw InsecureRuntimeConfigException(
          'origin must use https, got $origin',
        );
      }
    }
  }

  final Uri keycloakTokenUrl;
  final String keycloakClientId;
  final String keycloakClientSecret;
  final String localUsername;
  final String localPassword;
  final Uri gatewayBootstrapBaseUrl;
  final Uri gatewayBaseUrl;

  /// ML-DSA-87 root of the post-quantum chain.
  final String trustedCaAsset;

  /// ECDSA P-384 root of the compatibility chain (always trusted: a
  /// dual-identity listener may serve that chain to any ECDSA-capable client).
  final String compatTrustedCaAsset;
  final String appInstanceId;
  final String deviceId;
  final String certificateProfile;
  final String environment;

  /// Transport mode selection (`PQC_TRANSPORT_POLICY`).
  final TransportPolicy transportPolicy;

  /// CN of the PKI-issued identity that signs the envelope key set.
  final String envelopeSignerCommonName;

  factory RuntimeConfig.fromEnvironment() => RuntimeConfig.localDefaults(
    keycloakTokenUrl: Uri.parse(
      const String.fromEnvironment(
        'KEYCLOAK_TOKEN_URL',
        defaultValue:
            'https://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/token',
      ),
    ),
    keycloakClientId: const String.fromEnvironment(
      'KEYCLOAK_CLIENT_ID',
      defaultValue: 'quantum-bank-mobile',
    ),
    keycloakClientSecret: const String.fromEnvironment(
      'KEYCLOAK_CLIENT_SECRET',
    ),
    localUsername: const String.fromEnvironment(
      'KEYCLOAK_USERNAME',
      defaultValue: 'alice@quantumbank.local',
    ),
    // No default on purpose: a password must never be compiled into the
    // binary. Supply it with --dart-define=KEYCLOAK_PASSWORD=... for local runs.
    localPassword: const String.fromEnvironment('KEYCLOAK_PASSWORD'),
    gatewayBootstrapBaseUrl: Uri.parse(
      const String.fromEnvironment(
        'GATEWAY_BOOTSTRAP_BASE_URL',
        defaultValue: 'https://localhost:8080',
      ),
    ),
    gatewayBaseUrl: Uri.parse(
      const String.fromEnvironment(
        'GATEWAY_BASE_URL',
        defaultValue: 'https://localhost:8443',
      ),
    ),
    trustedCaAsset: const String.fromEnvironment(
      'TRUSTED_CA_ASSET',
      defaultValue: 'assets/local-ca/root-ca.crt',
    ),
    compatTrustedCaAsset: const String.fromEnvironment(
      'COMPAT_TRUSTED_CA_ASSET',
      defaultValue: 'assets/local-ca/root-ca-compat.crt',
    ),
    appInstanceId: const String.fromEnvironment(
      'APP_INSTANCE_ID',
      defaultValue: 'app-local-001',
    ),
    deviceId: const String.fromEnvironment(
      'DEVICE_ID',
      defaultValue: 'device-local-001',
    ),
    certificateProfile: const String.fromEnvironment(
      'CERTIFICATE_PROFILE',
      defaultValue: 'quantum-bank-mobile-client-v1',
    ),
    environment: const String.fromEnvironment(
      'QUANTUM_BANK_ENVIRONMENT',
      defaultValue: 'local',
    ),
    transportPolicy: TransportPolicy.parse(
      const String.fromEnvironment('PQC_TRANSPORT_POLICY', defaultValue: 'compatibility'),
    ),
    envelopeSignerCommonName: const String.fromEnvironment(
      'ENVELOPE_SIGNER_CN',
      defaultValue: 'backend',
    ),
  );

  factory RuntimeConfig.localDefaults({
    Uri? keycloakTokenUrl,
    String keycloakClientId = 'quantum-bank-mobile',
    String keycloakClientSecret = '',
    String localUsername = 'alice@quantumbank.local',
    String localPassword = '',
    Uri? gatewayBootstrapBaseUrl,
    Uri? gatewayBaseUrl,
    String trustedCaAsset = 'assets/local-ca/root-ca.crt',
    String compatTrustedCaAsset = 'assets/local-ca/root-ca-compat.crt',
    String appInstanceId = 'app-local-001',
    String deviceId = 'device-local-001',
    String certificateProfile = 'quantum-bank-mobile-client-v1',
    String environment = 'local',
    TransportPolicy transportPolicy = TransportPolicy.compatibility,
    String envelopeSignerCommonName = 'backend',
  }) => RuntimeConfig(
    keycloakTokenUrl:
        keycloakTokenUrl ??
        Uri.parse(
          'https://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/token',
        ),
    keycloakClientId: keycloakClientId,
    keycloakClientSecret: keycloakClientSecret,
    localUsername: localUsername,
    localPassword: localPassword,
    gatewayBootstrapBaseUrl:
        gatewayBootstrapBaseUrl ?? Uri.parse('https://localhost:8080'),
    gatewayBaseUrl: gatewayBaseUrl ?? Uri.parse('https://localhost:8443'),
    trustedCaAsset: trustedCaAsset,
    compatTrustedCaAsset: compatTrustedCaAsset,
    appInstanceId: appInstanceId,
    deviceId: deviceId,
    certificateProfile: certificateProfile,
    environment: environment,
    transportPolicy: transportPolicy,
    envelopeSignerCommonName: envelopeSignerCommonName,
  );
}
