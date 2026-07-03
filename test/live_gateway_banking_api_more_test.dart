import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/api/banking_client.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/core/api/live_gateway_banking_api.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';

class FakeBankingClient implements BankingGatewayClient {
  FakeBankingClient({this.response = const {}, this.problem});

  final Map<String, dynamic> response;
  final BankingHttpProblemException? problem;

  Future<Map<String, dynamic>> _reply() async {
    if (problem != null) {
      throw problem!;
    }
    return response;
  }

  @override
  Future<Map<String, dynamic>> createPixTransfer({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) => _reply();

  @override
  Future<Map<String, dynamic>> getStatements({
    required String bearerToken,
    required CertState certState,
  }) => _reply();

  @override
  Future<Map<String, dynamic>> getProfile({
    required String bearerToken,
    required CertState certState,
  }) => _reply();

  @override
  Future<Map<String, dynamic>> updateProfile({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) => _reply();
}

AuthSession validSession() => AuthSession(
  accessToken: 'token',
  subject: 'alice@quantumbank.local',
  expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
  scopes: const [],
);

LiveGatewayBankingApi apiWith({
  required BankingGatewayClient client,
  AuthSession? Function()? session,
}) => LiveGatewayBankingApi(
  bankingClient: client,
  authSessionProvider: session ?? validSession,
  certStateProvider: CertState.missing,
);

Future<PixResult> pix(LiveGatewayBankingApi api) => api.submitPix(
  amount: 10,
  recipientKey: 'recipient@example.com',
  description: 'test',
  scenario: PixScenario.success,
);

void main() {
  test('rejects the call when there is no auth session', () async {
    final api = apiWith(client: FakeBankingClient(), session: () => null);

    await expectLater(pix(api), throwsA(isA<StateError>()));
  });

  test('rejects the call when the auth session has expired', () async {
    final expired = AuthSession(
      accessToken: 'token',
      subject: 'alice@quantumbank.local',
      expiresAt: DateTime.now().toUtc().subtract(const Duration(hours: 1)),
      scopes: const [],
    );
    final api = apiWith(client: FakeBankingClient(), session: () => expired);

    await expectLater(pix(api), throwsA(isA<StateError>()));
  });

  test('parses a string amount and defaults a missing correlation id', () async {
    final api = apiWith(
      client: FakeBankingClient(
        response: {'transactionId': 'tx-1', 'status': 'ACCEPTED', 'amount': '12.34'},
      ),
    );

    final result = await pix(api);

    expect(result.amount, equals(12.34));
    expect(result.correlationId, equals(''));
  });

  test('maps a banking problem to a gateway problem with defaults', () async {
    final api = apiWith(
      client: FakeBankingClient(
        problem: const BankingHttpProblemException(statusCode: 500, problem: {}),
      ),
    );

    await expectLater(
      pix(api),
      throwsA(
        isA<GatewayProblemException>().having(
          (e) => e.problem.errorCode,
          'errorCode',
          'gateway_problem',
        ),
      ),
    );
  });
}
