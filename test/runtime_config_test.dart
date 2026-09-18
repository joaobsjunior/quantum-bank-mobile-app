import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';

void main() {
  test('fromEnvironment builds the local defaults', () {
    final config = RuntimeConfig.fromEnvironment();

    expect(config.keycloakClientId, equals('quantum-bank-mobile'));
    expect(config.localUsername, equals('alice@quantumbank.local'));
    expect(config.certificateProfile, equals('quantum-bank-mobile-client-v1'));
    expect(config.environment, equals('local'));
    expect(config.appInstanceId, equals('app-local-001'));
    expect(config.deviceId, equals('device-local-001'));
    expect(config.trustedCaAsset, equals('assets/local-ca/root-ca.crt'));
    expect(config.compatTrustedCaAsset, equals('assets/local-ca/root-ca-compat.crt'));
    expect(config.keycloakTokenUrl.toString(), contains('openid-connect/token'));
    expect(config.keycloakTokenUrl.scheme, equals('https'));
    expect(config.gatewayBootstrapBaseUrl.scheme, equals('https'));
    expect(config.gatewayBaseUrl.scheme, equals('https'));
    expect(config.localPassword, isEmpty);
  });

  test('rejects plaintext origins for the issuer and the gateway', () {
    expect(
      () => RuntimeConfig.localDefaults(
        keycloakTokenUrl: Uri.parse('http://localhost:8180/token'),
      ),
      throwsA(isA<InsecureRuntimeConfigException>()),
    );
    expect(
      () => RuntimeConfig.localDefaults(
        gatewayBaseUrl: Uri.parse('http://localhost:8443'),
      ),
      throwsA(
        isA<InsecureRuntimeConfigException>().having(
          (e) => e.toString(),
          'message',
          contains('must use https'),
        ),
      ),
    );
  });
}
