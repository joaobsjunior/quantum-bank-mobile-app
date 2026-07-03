import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/features/bootstrap/bootstrap_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';

Future<HttpServer> serve(void Function(HttpRequest request) handler) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen(handler);
  return server;
}

BootstrapClient clientFor(HttpServer server) => BootstrapClient(
  baseUrl: Uri.parse('http://127.0.0.1:${server.port}'),
  httpClient: HttpClient(),
);

void respondJson(HttpRequest request, int status, Map<String, dynamic> body) {
  request.response.statusCode = status;
  request.response.headers.contentType = ContentType.json;
  request.response.write(jsonEncode(body));
  request.response.close();
}

void main() {
  test('issueOtk parses the OTK and expiry', () async {
    final server = await serve(
      (request) => respondJson(request, 202, {
        'otk': 'otk-123',
        'expiresAt': '2026-05-21T10:05:00Z',
      }),
    );
    addTearDown(() => server.close(force: true));

    final result = await clientFor(server).issueOtk(
      bearerToken: 'token',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
      certificateProfile: 'quantum-bank-mobile-client-v1',
    );

    expect(result.otk, equals('otk-123'));
    expect(result.expiresAt, equals(DateTime.parse('2026-05-21T10:05:00Z')));
  });

  test('submitCsr joins the certificate chain', () async {
    final server = await serve(
      (request) => respondJson(request, 202, {
        'certificateChain': ['leaf-cert', 'issuing-cert'],
        'expiresAt': '2026-05-22T10:00:00Z',
      }),
    );
    addTearDown(() => server.close(force: true));

    final result = await submitCsr(clientFor(server));

    expect(utf8.decode(result.certificateChainBytes), equals('leaf-cert\nissuing-cert'));
  });

  test('submitCsr falls back to the single certificate field', () async {
    final server = await serve(
      (request) => respondJson(request, 202, {
        'certificate': 'leaf-only',
        'expiresAt': '2026-05-22T10:00:00Z',
      }),
    );
    addTearDown(() => server.close(force: true));

    final result = await submitCsr(clientFor(server));

    expect(utf8.decode(result.certificateChainBytes), equals('leaf-only'));
  });

  test('maps an HTTP error to a BootstrapProblem with the error code', () async {
    final server = await serve(
      (request) => respondJson(request, 409, {'errorCode': 'otk_replayed'}),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      submitCsr(clientFor(server)),
      throwsA(isA<BootstrapProblem>().having((e) => e.errorCode, 'errorCode', 'otk_replayed')),
    );
  });

  test('defaults the error code when the body has none', () async {
    final server = await serve((request) => respondJson(request, 500, {}));
    addTearDown(() => server.close(force: true));

    await expectLater(
      submitCsr(clientFor(server)),
      throwsA(isA<BootstrapProblem>().having((e) => e.errorCode, 'errorCode', 'bootstrap_failed')),
    );
  });

  test('defaults the error code when an error response has no body', () async {
    final server = await serve((request) {
      request.response.statusCode = 500;
      request.response.close();
    });
    addTearDown(() => server.close(force: true));

    await expectLater(
      submitCsr(clientFor(server)),
      throwsA(isA<BootstrapProblem>().having((e) => e.errorCode, 'errorCode', 'bootstrap_failed')),
    );
  });

  test('builds an HttpClient with and without a trusted CA', () {
    final caBytes = File('assets/local-ca/root-ca.crt').readAsBytesSync();

    expect(() => BootstrapClient(baseUrl: Uri.parse('https://localhost:8080')), returnsNormally);
    expect(
      () => BootstrapClient(
        baseUrl: Uri.parse('https://localhost:8080'),
        trustedCaBytes: caBytes,
      ),
      returnsNormally,
    );
  });
}

Future<CertificateEnrollmentResult> submitCsr(BootstrapClient client) => client.submitCsr(
  bearerToken: 'token',
  otk: 'otk-123',
  csrPem: 'csr',
  appInstanceId: 'app-local-001',
  deviceId: 'device-local-001',
  certificateProfile: 'quantum-bank-mobile-client-v1',
  environment: 'local',
);
