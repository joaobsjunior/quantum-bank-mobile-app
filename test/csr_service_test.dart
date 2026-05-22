import 'package:test/test.dart';
import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

void main() {
  test('generates runtime keypair and CSR with backend identity inputs', () {
    final keypair = KeypairService().generateRsaKeyPair();
    final input = CsrInput(
      oauth2Subject: 'alice@quantumbank.local',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
    );

    final csrPem = CsrService().generatePem(input: input, keyPair: keypair);

    expect(csrPem, contains('BEGIN CERTIFICATE REQUEST'));
    expect(input.oauth2Subject, equals('alice@quantumbank.local'));
    expect(input.appInstanceId, equals('app-local-001'));
    expect(input.deviceId, equals('device-local-001'));
    expect(input.certificateProfile, equals('quantum-bank-mobile-client-v1'));
    expect(input.environment, equals('local'));
    expect(
      input.subjectAlternativeNames,
      contains('urn:quantum-bank:app-instance:app-local-001'),
    );
    expect(
      input.subjectAlternativeNames,
      contains('urn:quantum-bank:device:device-local-001'),
    );
    expect(
      input.subjectAlternativeNames,
      contains('urn:quantum-bank:environment:local'),
    );
  });
}
