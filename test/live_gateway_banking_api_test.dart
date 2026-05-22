import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/banking_client.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/core/api/live_gateway_banking_api.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';

void main() {
  test(
    'submits Pix through banking client with bearer token and certificate state',
    () async {
      final client = RecordingBankingGatewayClient();
      final api = LiveGatewayBankingApi(
        bankingClient: client,
        authSessionProvider: () => authSession,
        certStateProvider: () => readyCert,
      );

      final result = await api.submitPix(
        amount: 25.3,
        recipientKey: 'recipient@example.com',
        description: 'Test pix',
        scenario: PixScenario.success,
      );

      expect(client.lastBearerToken, equals('access-token'));
      expect(client.lastCertState, same(readyCert));
      expect(client.lastPixPayload, containsPair('scenario', 'SUCCESS'));
      expect(result.transactionId, equals('pix-001'));
      expect(result.status, equals('COMPLETED'));
      expect(result.correlationId, equals('corr-001'));
    },
  );

  test(
    'maps banking problem responses to gateway problem exceptions',
    () async {
      final client = RecordingBankingGatewayClient()
        ..pixProblem = const BankingHttpProblemException(
          statusCode: 422,
          problem: {
            'errorCode': 'pix_simulated_error',
            'title': 'Pix simulation failed',
            'detail': 'Rejected by scenario',
            'correlationId': 'corr-error',
          },
        );
      final api = LiveGatewayBankingApi(
        bankingClient: client,
        authSessionProvider: () => authSession,
        certStateProvider: () => readyCert,
      );

      await expectLater(
        api.submitPix(
          amount: 25.3,
          recipientKey: 'recipient@example.com',
          description: 'Test pix',
          scenario: PixScenario.error,
        ),
        throwsA(
          isA<GatewayProblemException>().having(
            (exception) => exception.problem.errorCode,
            'errorCode',
            'pix_simulated_error',
          ),
        ),
      );
    },
  );

  test('loads statements and updates profile through live adapter', () async {
    final client = RecordingBankingGatewayClient();
    final api = LiveGatewayBankingApi(
      bankingClient: client,
      authSessionProvider: () => authSession,
      certStateProvider: () => readyCert,
    );

    final statements = await api.loadStatements();
    final profile = await api.loadProfile();
    final updated = await api.updateProfile(
      profile.copyWith(fullName: 'Alice Updated'),
    );

    expect(
      statements.single.description,
      equals('Pix recebido - Cafeteria Horizonte'),
    );
    expect(profile.email, equals('alice@quantumbank.local'));
    expect(
      client.lastProfilePayload,
      containsPair('fullName', 'Alice Updated'),
    );
    expect(updated.fullName, equals('Alice Updated'));
  });
}

final authSession = AuthSession(
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

final readyCert = CertState.ready(
  certificateChainBytes: const <int>[1, 2, 3],
  privateKeyBytes: const <int>[4, 5, 6],
  expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
);

class RecordingBankingGatewayClient implements BankingGatewayClient {
  String? lastBearerToken;
  CertState? lastCertState;
  Map<String, Object?>? lastPixPayload;
  Map<String, Object?>? lastProfilePayload;
  BankingHttpProblemException? pixProblem;

  @override
  Future<Map<String, dynamic>> createPixTransfer({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) async {
    lastBearerToken = bearerToken;
    lastCertState = certState;
    lastPixPayload = payload;
    final problem = pixProblem;
    if (problem != null) {
      throw problem;
    }

    return {
      'transactionId': 'pix-001',
      'status': 'COMPLETED',
      'amount': payload['amount'],
      'correlationId': 'corr-001',
    };
  }

  @override
  Future<Map<String, dynamic>> getStatements({
    required String bearerToken,
    required CertState certState,
  }) async => {
    'entries': [
      {
        'description': 'Pix recebido - Cafeteria Horizonte',
        'amount': 125.5,
        'type': 'CREDIT',
        'postedAt': '2026-05-20T09:30:00Z',
      },
    ],
  };

  @override
  Future<Map<String, dynamic>> getProfile({
    required String bearerToken,
    required CertState certState,
  }) async => {
    'fullName': 'Alice Quantum',
    'email': 'alice@quantumbank.local',
    'phone': '+55 71 90000-0001',
    'documentNumber': '123.456.789-00',
    'address': 'Av. Oceano Seguro, 100 - Salvador, BA',
  };

  @override
  Future<Map<String, dynamic>> updateProfile({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) async {
    lastBearerToken = bearerToken;
    lastCertState = certState;
    lastProfilePayload = payload;
    return {
      'fullName': payload['fullName'],
      'email': payload['email'],
      'phone': payload['phone'],
      'documentNumber': '123.456.789-00',
      'address': payload['address'],
    };
  }
}
