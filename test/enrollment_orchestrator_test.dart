import 'dart:convert';

import 'package:pointycastle/export.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

class FakeKeypairService extends KeypairService {
  @override
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKeyPair({int bitLength = 2048}) =>
      AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
        RSAPublicKey(BigInt.from(3233), BigInt.from(17)),
        RSAPrivateKey(BigInt.from(3233), BigInt.from(2753), BigInt.from(61), BigInt.from(53)),
      );

  @override
  String encodePrivateKeyPem(RSAPrivateKey privateKey) => 'FAKE-PEM';
}

class FakeCsrService extends CsrService {
  @override
  String generatePem({
    required CsrInput input,
    required AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair,
  }) => 'FAKE-CSR';
}

class FakeBootstrapGateway implements BootstrapGateway {
  FakeBootstrapGateway({this.problem});

  final BootstrapProblem? problem;

  @override
  Future<OtkIssueResult> issueOtk({
    required String bearerToken,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
  }) async {
    if (problem != null) {
      throw problem!;
    }
    return OtkIssueResult(otk: 'otk-1', expiresAt: DateTime.utc(2026, 5, 21, 10, 5));
  }

  @override
  Future<CertificateEnrollmentResult> submitCsr({
    required String bearerToken,
    required String otk,
    required String csrPem,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async => CertificateEnrollmentResult(
    certificateChainBytes: utf8.encode('leaf\nissuing'),
    expiresAt: DateTime.utc(2026, 5, 22, 10),
  );
}

EnrollmentOrchestrator orchestrator({BootstrapProblem? problem}) => EnrollmentOrchestrator(
  bootstrapGateway: FakeBootstrapGateway(problem: problem),
  keypairService: FakeKeypairService(),
  csrService: FakeCsrService(),
);

Future<CertState> enroll(EnrollmentOrchestrator o) => o.enroll(
  bearerToken: 'token',
  oauth2Subject: 'alice@quantumbank.local',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
);

void main() {
  test('happy path returns a ready certificate state with metadata', () async {
    final state = await enroll(orchestrator());

    expect(state, isA<ReadyCertState>());
    final ready = state as ReadyCertState;
    expect(utf8.decode(ready.certificateChainBytes), equals('leaf\nissuing'));
    expect(utf8.decode(ready.privateKeyBytes), equals('FAKE-PEM'));
    expect(ready.certificateProfile, equals('quantum-bank-mobile-client-v1'));
    expect(ready.environment, equals('local'));
  });

  test('maps bootstrap problems to certificate failure states', () async {
    expect(
      await enroll(orchestrator(problem: const BootstrapProblem('otk_expired'))),
      isA<OtkExpiredCertState>(),
    );
    expect(
      await enroll(orchestrator(problem: const BootstrapProblem('otk_replayed'))),
      isA<OtkReplayedCertState>(),
    );
    for (final code in ['csr_invalid', 'private_key_rejected', 'certificate_profile_mismatch', 'unknown']) {
      expect(
        await enroll(orchestrator(problem: BootstrapProblem(code))),
        isA<CsrRejectedCertState>(),
        reason: 'code $code should map to csrRejected',
      );
    }
  });
}
