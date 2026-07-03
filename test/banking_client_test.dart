import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/api/banking_client.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/core/tls/secure_context_factory.dart';

/// Returns a plain context so the client can talk to a local HTTP test server
/// without real mTLS material.
class PlainSecureContextFactory extends SecureContextFactory {
  @override
  SecurityContext build({
    required List<int> trustedCaBytes,
    required List<int> certificateChainBytes,
    required List<int> privateKeyBytes,
  }) => SecurityContext(withTrustedRoots: true);
}

Future<HttpServer> serve(void Function(HttpRequest request) handler) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen(handler);
  return server;
}

CertState readyCert() => CertState.ready(
  certificateChainBytes: const <int>[1, 2, 3],
  privateKeyBytes: const <int>[4, 5, 6],
  expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
);

BankingClient clientFor(HttpServer server) => BankingClient(
  gatewayBaseUrl: Uri.parse('http://127.0.0.1:${server.port}'),
  trustedCaBytes: const <int>[1],
  secureContextFactory: PlainSecureContextFactory(),
);

void respondJson(HttpRequest request, int status, Map<String, dynamic> body) {
  request.response.statusCode = status;
  request.response.headers.contentType = ContentType.json;
  request.response.write(jsonEncode(body));
  request.response.close();
}

void main() {
  test('sends a Pix transfer and returns the decoded body', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {'transactionId': 'tx-1', 'status': 'ACCEPTED'}),
    );
    addTearDown(() => server.close(force: true));

    final response = await clientFor(server).createPixTransfer(
      bearerToken: 'token',
      certState: readyCert(),
      payload: {'amount': 10},
    );

    expect(response['transactionId'], equals('tx-1'));
  });

  test('reads statements, profile and updates profile', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {'ok': true}),
    );
    addTearDown(() => server.close(force: true));

    final client = clientFor(server);
    expect((await client.getStatements(bearerToken: 't', certState: readyCert()))['ok'], isTrue);
    expect((await client.getProfile(bearerToken: 't', certState: readyCert()))['ok'], isTrue);
    expect(
      (await client.updateProfile(bearerToken: 't', certState: readyCert(), payload: {'a': 1}))['ok'],
      isTrue,
    );
  });

  test('returns an empty map when the response has no body', () async {
    final server = await serve((request) {
      request.response.statusCode = 200;
      request.response.close();
    });
    addTearDown(() => server.close(force: true));

    final response = await clientFor(server).getStatements(bearerToken: 't', certState: readyCert());

    expect(response, isEmpty);
  });

  test('maps an HTTP error to a BankingHttpProblemException', () async {
    final server = await serve(
      (request) => respondJson(request, 422, {'errorCode': 'pix_error'}),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).getStatements(bearerToken: 't', certState: readyCert()),
      throwsA(
        isA<BankingHttpProblemException>().having((e) => e.statusCode, 'statusCode', 422),
      ),
    );
  });

  test('rejects a request when the certificate is missing or expired', () async {
    final client = BankingClient(
      gatewayBaseUrl: Uri.parse('http://127.0.0.1:1'),
      trustedCaBytes: const <int>[1],
      secureContextFactory: PlainSecureContextFactory(),
    );

    await expectLater(
      client.getStatements(bearerToken: 't', certState: CertState.missing()),
      throwsA(isA<BankingClientCertificateException>()),
    );

    final expired = CertState.ready(
      certificateChainBytes: const <int>[1],
      privateKeyBytes: const <int>[2],
      expiresAt: DateTime.now().toUtc().subtract(const Duration(hours: 1)),
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
    );
    await expectLater(
      client.getStatements(bearerToken: 't', certState: expired),
      throwsA(isA<BankingClientCertificateException>()),
    );
  });

  test('BankingHttpProblemException and certificate exception describe themselves', () {
    expect(
      const BankingHttpProblemException(statusCode: 400, problem: {'a': 1}).toString(),
      contains('BankingHttpProblemException(400)'),
    );
    expect(
      const BankingClientCertificateException('missing').toString(),
      equals('BankingClientCertificateException: missing'),
    );
  });
}
