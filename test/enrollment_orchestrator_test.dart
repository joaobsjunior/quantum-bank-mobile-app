import 'dart:convert';

import 'dart:typed_data';

import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
import 'package:quantum_bank_mobile/core/tls/pqc_tls_support.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

class FakeKeypairService extends KeypairService {
  final List<TransportMode> requestedModes = [];

  @override
  DeviceKeyPair generateForTransport(TransportMode mode) {
    requestedModes.add(mode);
    return generateMlDsaKeyPair();
  }

  @override
  MlDsaKeyPair generateMlDsaKeyPair({MlDsaLevel level = MlDsaLevel.mlDsa65}) =>
      MlDsaKeyPair(
        level: level,
        publicKey: Uint8List(0),
        privateKey: Uint8List(0),
        seed: Uint8List(32),
      );

  @override
  String encodePrivateKeyPem(DeviceKeyPair keyPair) => 'FAKE-PEM';
}

class FakeCsrService extends CsrService {
  @override
  String generatePem({required CsrInput input, required DeviceKeyPair keyPair}) =>
      'FAKE-CSR';
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

EnrollmentOrchestrator orchestrator({
  BootstrapProblem? problem,
  FakeKeypairService? keypairService,
  TransportMode transportMode = TransportMode.postQuantum,
}) => EnrollmentOrchestrator(
  bootstrapGateway: FakeBootstrapGateway(problem: problem),
  transportMode: transportMode,
  keypairService: keypairService ?? FakeKeypairService(),
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

  test('requests the device key family of the transport mode', () async {
    final postQuantumKeys = FakeKeypairService();
    await enroll(orchestrator(keypairService: postQuantumKeys));
    expect(postQuantumKeys.requestedModes, equals([TransportMode.postQuantum]));
    expect(orchestrator().transportMode, TransportMode.postQuantum);

    final compatKeys = FakeKeypairService();
    final compat = orchestrator(
      keypairService: compatKeys,
      transportMode: TransportMode.compatibility,
    );
    await enroll(compat);
    expect(compatKeys.requestedModes, equals([TransportMode.compatibility]));
    expect(compat.transportMode, TransportMode.compatibility);
  });

  test('enrolls a real ECDSA P-256 identity in compatibility mode', () async {
    final orchestrated = EnrollmentOrchestrator(
      bootstrapGateway: FakeBootstrapGateway(),
      transportMode: TransportMode.compatibility,
    );

    final state = await enroll(orchestrated) as ReadyCertState;

    final pem = utf8.decode(state.privateKeyBytes);
    expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));
    final der = PqcAsn1.derFromPem(pem, PqcAsn1.pkcs8Label);
    // id-ecPublicKey OID inside the PKCS#8 AlgorithmIdentifier.
    expect(der, containsAllInOrder([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]));
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
