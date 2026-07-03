import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';

void main() {
  test('models certificate-ready failure states', () {
    expect(CertState.missing().name, equals('missing'));
    expect(CertState.expired().name, equals('expired'));
    expect(CertState.untrusted().name, equals('untrusted'));
    expect(CertState.csrRejected().name, equals('csrRejected'));
    expect(CertState.otkExpired().name, equals('otkExpired'));
    expect(CertState.otkReplayed().name, equals('otkReplayed'));
  });

  test('ready state keeps certificate lifecycle metadata together', () {
    final expiresAt = DateTime.utc(2026, 5, 22, 12);
    final state = CertState.ready(
      certificateChainBytes: const <int>[1, 2, 3],
      privateKeyBytes: const <int>[4, 5, 6],
      expiresAt: expiresAt,
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
    );

    expect(state.name, equals('ready'));
    expect(state.isReadyAt(DateTime.utc(2026, 5, 22, 11)), isTrue);
    expect(state.isReadyAt(DateTime.utc(2026, 5, 22, 13)), isFalse);
    expect(state.certificateProfile, equals('quantum-bank-mobile-client-v1'));
    expect(state.environment, equals('local'));
    expect(state.appInstanceId, equals('app-local-001'));
    expect(state.deviceId, equals('device-local-001'));
  });

  test('non-ready states expose null metadata and are never ready', () {
    final states = [
      CertState.missing(),
      CertState.expired(),
      CertState.untrusted(),
      CertState.csrRejected(),
      CertState.otkExpired(),
      CertState.otkReplayed(),
    ];

    for (final state in states) {
      expect(state.certificateChainBytes, isNull);
      expect(state.privateKeyBytes, isNull);
      expect(state.expiresAt, isNull);
      expect(state.certificateProfile, isNull);
      expect(state.environment, isNull);
      expect(state.appInstanceId, isNull);
      expect(state.deviceId, isNull);
      expect(state.isReadyAt(DateTime.now().toUtc()), isFalse);
    }
  });
}
