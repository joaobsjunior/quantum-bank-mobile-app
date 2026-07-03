import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/app/app_state.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';
import 'package:quantum_bank_mobile/features/profile/profile_screen.dart';
import 'package:quantum_bank_mobile/features/statements/statement_screen.dart';
import 'package:quantum_bank_mobile/main.dart' as app;

class _NoopAuthenticator implements Authenticator {
  @override
  Future<AuthSession> authenticate() async => throw UnimplementedError();
}

class _NoopEnrollment implements CertificateEnrollment {
  @override
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async => throw UnimplementedError();
}

QuantumBankAppState gateState() => QuantumBankAppState(
  authenticator: _NoopAuthenticator(),
  certificateEnrollment: _NoopEnrollment(),
  runtimeConfig: RuntimeConfig.localDefaults(),
);

Future<void> pumpApp(WidgetTester tester, QuantumBankAppState state) =>
    tester.pumpWidget(app.QuantumBankApp(api: DemoGatewayBankingApi(), appState: state));

CertState readyCert() => CertState.ready(
  certificateChainBytes: const <int>[1],
  privateKeyBytes: const <int>[2],
  expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
);

void main() {
  testWidgets('shows the authenticating state with a disabled button', (tester) async {
    final state = gateState()..authenticating = true;

    await pumpApp(tester, state);

    expect(find.text('Autenticando...'), findsOneWidget);
  });

  testWidgets('shows the certificate-activation state', (tester) async {
    final state = gateState()
      ..authenticated = true
      ..enrollingCertificate = true;

    await pumpApp(tester, state);

    expect(find.text('Ativando...'), findsOneWidget);
    expect(find.text('Certificado do dispositivo pendente.'), findsOneWidget);
  });

  testWidgets('renders the last error message', (tester) async {
    final state = gateState()..lastError = 'algo deu errado';

    await pumpApp(tester, state);

    expect(find.text('algo deu errado'), findsOneWidget);
  });

  testWidgets('switches between Pix, Extrato and Perfil once protected', (tester) async {
    final state = gateState()
      ..authenticated = true
      ..certificateState = readyCert();

    await pumpApp(tester, state);
    await tester.pumpAndSettle();

    await tester.tap(find.text('Extrato'));
    await tester.pumpAndSettle();
    expect(find.byType(StatementScreen), findsOneWidget);

    await tester.tap(find.text('Perfil'));
    await tester.pumpAndSettle();
    expect(find.byType(ProfileScreen), findsOneWidget);
  });

  testWidgets('main boots the protected gate', (tester) async {
    await app.main();
    await tester.pumpAndSettle();

    expect(find.text('Acesso protegido'), findsOneWidget);
  });
}
