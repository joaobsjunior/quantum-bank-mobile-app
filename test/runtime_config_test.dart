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
    expect(config.keycloakTokenUrl.toString(), contains('openid-connect/token'));
  });
}
