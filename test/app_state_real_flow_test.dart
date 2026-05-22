import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/app/app_state.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';

void main() {
  test(
    'authenticate stores a real auth session from the configured authenticator',
    () async {
      final authenticator = RecordingAuthenticator();
      final state = QuantumBankAppState(
        authenticator: authenticator,
        certificateEnrollment: RecordingCertificateEnrollment(),
        runtimeConfig: RuntimeConfig.localDefaults(),
      );

      await state.authenticate();

      expect(authenticator.called, isTrue);
      expect(state.authenticated, isTrue);
      expect(state.authSession?.accessToken, equals('access-token'));
      expect(
        state.authSession?.subject,
        equals('00000000-0000-0000-0000-000000000001'),
      );
      expect(state.lastError, isNull);
    },
  );

  test(
    'certificate activation enrolls through bootstrap using token subject and runtime identifiers',
    () async {
      final enrollment = RecordingCertificateEnrollment();
      final state = QuantumBankAppState(
        authenticator: RecordingAuthenticator(),
        certificateEnrollment: enrollment,
        runtimeConfig: RuntimeConfig.localDefaults(),
      );

      await state.authenticate();
      await state.markCertificateReady();

      expect(enrollment.bearerToken, equals('access-token'));
      expect(
        enrollment.oauth2Subject,
        equals('00000000-0000-0000-0000-000000000001'),
      );
      expect(enrollment.appInstanceId, equals('app-local-001'));
      expect(enrollment.deviceId, equals('device-local-001'));
      expect(
        enrollment.certificateProfile,
        equals('quantum-bank-mobile-client-v1'),
      );
      expect(enrollment.environment, equals('local'));
      expect(state.certificateReady, isTrue);
      expect(state.protectedReady, isTrue);
    },
  );
}

class RecordingAuthenticator implements Authenticator {
  bool called = false;

  @override
  Future<AuthSession> authenticate() async {
    called = true;
    return AuthSession(
      accessToken: 'access-token',
      subject: '00000000-0000-0000-0000-000000000001',
      expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      scopes: const [
        'profile:read',
        'pix:write',
        'statements:read',
        'profile:write',
      ],
    );
  }
}

class RecordingCertificateEnrollment implements CertificateEnrollment {
  String? bearerToken;
  String? oauth2Subject;
  String? appInstanceId;
  String? deviceId;
  String? certificateProfile;
  String? environment;

  @override
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async {
    this.bearerToken = bearerToken;
    this.oauth2Subject = oauth2Subject;
    this.appInstanceId = appInstanceId;
    this.deviceId = deviceId;
    this.certificateProfile = certificateProfile;
    this.environment = environment;

    return CertState.ready(
      certificateChainBytes: const <int>[1, 2, 3],
      privateKeyBytes: const <int>[4, 5, 6],
      expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      certificateProfile: certificateProfile,
      environment: environment,
      appInstanceId: appInstanceId,
      deviceId: deviceId,
    );
  }
}
