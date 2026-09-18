import 'package:test/test.dart';
import 'package:quantum_bank_mobile/app/app_state.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/core/tls/pqc_tls_support.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';

class ThrowingAuthenticator implements Authenticator {
  @override
  Future<AuthSession> authenticate() async => throw StateError('auth-boom');
}

class OkAuthenticator implements Authenticator {
  @override
  Future<AuthSession> authenticate() async => AuthSession(
    accessToken: 'access-token',
    subject: 'alice@quantumbank.local',
    expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
    scopes: const [],
  );
}

class ReturningEnrollment implements CertificateEnrollment {
  ReturningEnrollment(this._state);

  final CertState _state;

  @override
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async => _state;
}

class ThrowingEnrollment implements CertificateEnrollment {
  @override
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async => throw StateError('enroll-boom');
}

QuantumBankAppState stateWith({
  required Authenticator authenticator,
  required CertificateEnrollment enrollment,
  PqcTransportStatus pqcTransport = const PqcTransportStatus.supported(),
}) => QuantumBankAppState(
  authenticator: authenticator,
  certificateEnrollment: enrollment,
  runtimeConfig: RuntimeConfig.localDefaults(),
  pqcTransport: pqcTransport,
);

void main() {
  test('authenticate records the error when the authenticator fails', () async {
    final state = stateWith(
      authenticator: ThrowingAuthenticator(),
      enrollment: ReturningEnrollment(CertState.missing()),
    );

    await state.authenticate();

    expect(state.authenticated, isFalse);
    expect(state.authSession, isNull);
    expect(state.lastError, contains('auth-boom'));
  });

  test('markCertificateReady requires an authenticated session first', () async {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ReturningEnrollment(CertState.missing()),
    );

    await state.markCertificateReady();

    expect(state.lastError, equals('Authenticate before activating the device certificate.'));
    expect(state.certificateReady, isFalse);
  });

  test('markCertificateReady reports a non-ready enrollment outcome', () async {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ReturningEnrollment(CertState.csrRejected()),
    );

    await state.authenticate();
    await state.markCertificateReady();

    expect(state.certificateReady, isFalse);
    expect(state.lastError, equals('Certificate enrollment failed: csrRejected'));
  });

  test('markCertificateReady maps a thrown enrollment error to csrRejected', () async {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ThrowingEnrollment(),
    );

    await state.authenticate();
    await state.markCertificateReady();

    expect(state.certificateState, isA<CsrRejectedCertState>());
    expect(state.lastError, contains('enroll-boom'));
  });

  test('post-quantum transport is supported by default and gates protected access', () async {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ReturningEnrollment(
        CertState.ready(
          certificateChainBytes: const <int>[1],
          privateKeyBytes: const <int>[2],
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
          certificateProfile: 'quantum-bank-mobile-client-v1',
          environment: 'local',
          appInstanceId: 'app-local-001',
          deviceId: 'device-local-001',
        ),
      ),
    );

    expect(state.pqcTransportSupported, isTrue);
    await state.authenticate();
    await state.markCertificateReady();
    expect(state.protectedReady, isTrue);
  });

  test('an unsupported post-quantum transport runs in compatibility mode', () async {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ReturningEnrollment(
        CertState.ready(
          certificateChainBytes: const <int>[1],
          privateKeyBytes: const <int>[2],
          expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
          certificateProfile: 'quantum-bank-mobile-client-v1',
          environment: 'local',
          appInstanceId: 'app-local-001',
          deviceId: 'device-local-001',
        ),
      ),
      pqcTransport: const PqcTransportStatus.unsupported('no ML-DSA in TLS stack'),
    );

    expect(state.pqcTransportSupported, isFalse);
    expect(state.transportMode, TransportMode.compatibility);
    expect(state.transportLabel, contains('compatibilidade'));
    expect(state.transportLabel, contains('ECDSA P-256'));

    await state.authenticate();
    await state.markCertificateReady();

    // Compatibility is a first-class PKI-issued identity: protected access
    // opens once authentication and enrollment complete.
    expect(state.protectedReady, isTrue);
  });

  test('a post-quantum transport is labelled as such', () {
    final state = stateWith(
      authenticator: OkAuthenticator(),
      enrollment: ReturningEnrollment(CertState.missing()),
    );

    expect(state.transportMode, TransportMode.postQuantum);
    expect(state.transportLabel, contains('ML-DSA-65'));
    expect(state.transportLabel, contains('X25519MLKEM768'));
  });
}
