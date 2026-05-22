import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/app/app_state.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';
import 'package:quantum_bank_mobile/main.dart';

void main() {
  testWidgets(
    'blocks protected screens until authenticated and certificateReady',
    (tester) async {
      await tester.pumpWidget(
        QuantumBankApp(
          api: DemoGatewayBankingApi(),
          appState: QuantumBankAppState(
            authenticator: _TestAuthenticator(),
            certificateEnrollment: _TestCertificateEnrollment(),
            runtimeConfig: RuntimeConfig.localDefaults(),
          ),
        ),
      );

      expect(find.text('Acesso protegido'), findsOneWidget);
      expect(find.text('Pix'), findsNothing);

      await tester.tap(find.text('Autenticar'));
      await tester.pumpAndSettle();

      expect(find.text('Certificado do dispositivo pendente.'), findsOneWidget);
      expect(find.text('Pix'), findsNothing);

      await tester.tap(find.text('Ativar certificado'));
      await tester.pumpAndSettle();

      expect(find.text('Pix'), findsWidgets);
      expect(find.text('Extrato'), findsOneWidget);
      expect(find.text('Perfil'), findsOneWidget);
    },
  );
}

class _TestAuthenticator implements Authenticator {
  @override
  Future<AuthSession> authenticate() async => AuthSession(
    accessToken: 'access-token',
    subject: '00000000-0000-0000-0000-000000000001',
    expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
    scopes: const ['profile:read'],
  );
}

class _TestCertificateEnrollment implements CertificateEnrollment {
  @override
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async => CertState.ready(
    certificateChainBytes: const <int>[1, 2, 3],
    privateKeyBytes: const <int>[4, 5, 6],
    expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
    certificateProfile: certificateProfile,
    environment: environment,
    appInstanceId: appInstanceId,
    deviceId: deviceId,
  );
}
