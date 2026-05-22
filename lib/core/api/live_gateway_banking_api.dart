import '../../features/auth/auth_client.dart';
import '../tls/cert_state.dart';
import 'banking_client.dart';
import 'gateway_api.dart';

class LiveGatewayBankingApi implements GatewayBankingApi {
  const LiveGatewayBankingApi({
    required BankingGatewayClient bankingClient,
    required AuthSession? Function() authSessionProvider,
    required CertState Function() certStateProvider,
  }) : _bankingClient = bankingClient,
       _authSessionProvider = authSessionProvider,
       _certStateProvider = certStateProvider;

  final BankingGatewayClient _bankingClient;
  final AuthSession? Function() _authSessionProvider;
  final CertState Function() _certStateProvider;

  @override
  Future<PixResult> submitPix({
    required double amount,
    required String recipientKey,
    required String description,
    required PixScenario scenario,
  }) async {
    final response = await _callGateway(
      (session, certState) => _bankingClient.createPixTransfer(
        bearerToken: session.accessToken,
        certState: certState,
        payload: {
          'amount': amount,
          'recipientKey': recipientKey,
          'description': description,
          'scenario': scenario.name.toUpperCase(),
        },
      ),
    );

    return PixResult(
      transactionId: response['transactionId'] as String,
      status: response['status'] as String,
      amount: _double(response['amount']),
      correlationId: response['correlationId'] as String? ?? '',
    );
  }

  @override
  Future<List<StatementItem>> loadStatements() async {
    final response = await _callGateway(
      (session, certState) => _bankingClient.getStatements(
        bearerToken: session.accessToken,
        certState: certState,
      ),
    );
    final entries = response['entries'] as List<dynamic>? ?? <dynamic>[];

    return entries
        .map((entry) {
          final statement = Map<String, dynamic>.from(entry as Map);
          return StatementItem(
            description: statement['description'] as String,
            amount: _double(statement['amount']),
            type: (statement['type'] as Object).toString(),
            postedAt: DateTime.parse(statement['postedAt'] as String),
          );
        })
        .toList(growable: false);
  }

  @override
  Future<CustomerProfile> loadProfile() async {
    final response = await _callGateway(
      (session, certState) => _bankingClient.getProfile(
        bearerToken: session.accessToken,
        certState: certState,
      ),
    );
    return _profileFrom(response);
  }

  @override
  Future<CustomerProfile> updateProfile(CustomerProfile profile) async {
    final response = await _callGateway(
      (session, certState) => _bankingClient.updateProfile(
        bearerToken: session.accessToken,
        certState: certState,
        payload: {
          'fullName': profile.fullName,
          'email': profile.email,
          'phone': profile.phone,
          'address': profile.address,
        },
      ),
    );
    return _profileFrom(response);
  }

  Future<Map<String, dynamic>> _callGateway(
    Future<Map<String, dynamic>> Function(
      AuthSession session,
      CertState certState,
    )
    call,
  ) async {
    final session = _authSessionProvider();
    if (session == null || !session.isValidAt(DateTime.now().toUtc())) {
      throw StateError('auth_session_missing_or_expired');
    }

    try {
      return await call(session, _certStateProvider());
    } on BankingHttpProblemException catch (exception) {
      throw GatewayProblemException(
        GatewayProblem(
          errorCode:
              exception.problem['errorCode'] as String? ?? 'gateway_problem',
          title: exception.problem['title'] as String? ?? 'Gateway problem',
          detail:
              exception.problem['detail'] as String? ??
              'The gateway returned HTTP ${exception.statusCode}.',
          correlationId: exception.problem['correlationId'] as String? ?? '',
        ),
      );
    }
  }

  CustomerProfile _profileFrom(Map<String, dynamic> response) =>
      CustomerProfile(
        fullName: response['fullName'] as String,
        email: response['email'] as String,
        phone: response['phone'] as String,
        documentNumber: response['documentNumber'] as String,
        address: response['address'] as String,
      );

  double _double(Object? value) {
    if (value is num) {
      return value.toDouble();
    }

    return double.parse(value.toString());
  }
}
