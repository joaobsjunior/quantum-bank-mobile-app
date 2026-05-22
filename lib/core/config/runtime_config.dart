class RuntimeConfig {
  const RuntimeConfig({
    required this.keycloakTokenUrl,
    required this.keycloakClientId,
    required this.keycloakClientSecret,
    required this.localUsername,
    required this.localPassword,
    required this.gatewayBootstrapBaseUrl,
    required this.gatewayBaseUrl,
    required this.trustedCaAsset,
    required this.appInstanceId,
    required this.deviceId,
    required this.certificateProfile,
    required this.environment,
  });

  final Uri keycloakTokenUrl;
  final String keycloakClientId;
  final String keycloakClientSecret;
  final String localUsername;
  final String localPassword;
  final Uri gatewayBootstrapBaseUrl;
  final Uri gatewayBaseUrl;
  final String trustedCaAsset;
  final String appInstanceId;
  final String deviceId;
  final String certificateProfile;
  final String environment;

  factory RuntimeConfig.fromEnvironment() => RuntimeConfig.localDefaults(
    keycloakTokenUrl: Uri.parse(
      const String.fromEnvironment(
        'KEYCLOAK_TOKEN_URL',
        defaultValue:
            'http://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/token',
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
    localPassword: const String.fromEnvironment(
      'KEYCLOAK_PASSWORD',
      defaultValue: 'change-me-local-only',
    ),
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
  );

  factory RuntimeConfig.localDefaults({
    Uri? keycloakTokenUrl,
    String keycloakClientId = 'quantum-bank-mobile',
    String keycloakClientSecret = '',
    String localUsername = 'alice@quantumbank.local',
    String localPassword = 'change-me-local-only',
    Uri? gatewayBootstrapBaseUrl,
    Uri? gatewayBaseUrl,
    String trustedCaAsset = 'assets/local-ca/root-ca.crt',
    String appInstanceId = 'app-local-001',
    String deviceId = 'device-local-001',
    String certificateProfile = 'quantum-bank-mobile-client-v1',
    String environment = 'local',
  }) => RuntimeConfig(
    keycloakTokenUrl:
        keycloakTokenUrl ??
        Uri.parse(
          'http://localhost:8180/realms/quantum-bank-local/protocol/openid-connect/token',
        ),
    keycloakClientId: keycloakClientId,
    keycloakClientSecret: keycloakClientSecret,
    localUsername: localUsername,
    localPassword: localPassword,
    gatewayBootstrapBaseUrl:
        gatewayBootstrapBaseUrl ?? Uri.parse('https://localhost:8080'),
    gatewayBaseUrl: gatewayBaseUrl ?? Uri.parse('https://localhost:8443'),
    trustedCaAsset: trustedCaAsset,
    appInstanceId: appInstanceId,
    deviceId: deviceId,
    certificateProfile: certificateProfile,
    environment: environment,
  );
}
