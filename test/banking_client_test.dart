import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/api/banking_client.dart';
import 'package:quantum_bank_mobile/core/pqc/hybrid_envelope.dart';
import 'package:quantum_bank_mobile/core/pqc/transaction_signer.dart';
import 'package:quantum_bank_mobile/core/tls/cert_state.dart';
import 'package:quantum_bank_mobile/core/tls/secure_context_factory.dart';

import 'support/envelope_test_server.dart';

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

late EnvelopeTestServer envelopeServer;
final signingKey = DeviceSigningKey.fromSeed(Uint8List.fromList(List<int>.filled(32, 3)));

Future<HttpServer> serve(Future<void> Function(HttpRequest request) handler) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen(handler);
  return server;
}

CertState readyCert({DateTime? expiresAt, bool withEnvelope = true, bool withSigningKey = true}) =>
    CertState.ready(
      certificateChainBytes: const <int>[1, 2, 3],
      privateKeyBytes: const <int>[4, 5, 6],
      expiresAt: expiresAt ?? DateTime.now().toUtc().add(const Duration(hours: 1)),
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
      envelopeKeySet: withEnvelope ? envelopeServer.keySet : null,
      signingKey: withSigningKey ? signingKey : null,
    );

BankingClient clientFor(HttpServer server) => BankingClient(
  gatewayBaseUrl: Uri.parse('http://127.0.0.1:${server.port}'),
  trustedCaBytes: const <int>[1],
  secureContextFactory: PlainSecureContextFactory(),
);

/// Opens the request envelope (body or header) like the backend filter and
/// returns the plaintext plus the response key.
Future<(String, Uint8List)> openRequest(HttpRequest request) async {
  final aad = '${request.method} ${request.uri.path}';
  final headerValue = request.headers.value(EnvelopeMessage.requestHeader);
  final EnvelopeMessage message;
  if (headerValue != null) {
    message = EnvelopeMessage.fromHeader(headerValue);
  } else {
    expect(request.headers.contentType!.mimeType, equals(EnvelopeMessage.mediaType));
    message = EnvelopeMessage.fromJson(jsonDecode(await utf8.decodeStream(request)) as Map<String, dynamic>);
  }
  final (plaintext, responseKey) = await envelopeServer.open(message, aad);
  return (utf8.decode(plaintext), responseKey);
}

Future<void> respondEnveloped(
  HttpRequest request,
  int status,
  Map<String, dynamic> body, {
  String contentType = 'application/json',
  Uint8List? responseKey,
}) async {
  final key = responseKey ?? (await openRequest(request)).$2;
  final message = envelopeServer.sealResponse(
    responseKey: key,
    kid: envelopeServer.keySet.kid,
    aad: '${request.method} ${request.uri.path}',
    body: jsonEncode(body),
    contentType: contentType,
  );
  request.response.statusCode = status;
  request.response.headers.contentType = ContentType.parse(EnvelopeMessage.mediaType);
  request.response.headers.set(EnvelopeMessage.contentTypeHeader, contentType);
  request.response.write(jsonEncode(message.toJson()));
  await request.response.close();
}

void respondJson(HttpRequest request, int status, Map<String, dynamic> body) {
  request.response.statusCode = status;
  request.response.headers.contentType = ContentType.json;
  request.response.write(jsonEncode(body));
  request.response.close();
}

void main() {
  setUpAll(() async {
    envelopeServer = await EnvelopeTestServer.create();
  });

  test('seals a Pix transfer in the request body and opens the enveloped response', () async {
    String? seenPlaintext;
    final server = await serve((request) async {
      final (plaintext, responseKey) = await openRequest(request);
      seenPlaintext = plaintext;
      await respondEnveloped(request, 200, {'transactionId': 'tx-1', 'status': 'ACCEPTED'}, responseKey: responseKey);
    });
    addTearDown(() => server.close(force: true));

    final response = await clientFor(server).createPixTransfer(
      bearerToken: 'token',
      certState: readyCert(),
      payload: {'amount': 10},
    );

    expect(seenPlaintext, equals('{"amount":10}'));
    expect(response['transactionId'], equals('tx-1'));
  });

  test('sends the encapsulation in a header for GET requests and opens every response', () async {
    final headers = <String, String?>{};
    final server = await serve((request) async {
      headers['${request.method} ${request.uri.path}'] = request.headers.value(EnvelopeMessage.requestHeader);
      await respondEnveloped(request, 200, {'ok': true});
    });
    addTearDown(() => server.close(force: true));

    final client = clientFor(server);
    expect((await client.getStatements(bearerToken: 't', certState: readyCert()))['ok'], isTrue);
    expect((await client.getProfile(bearerToken: 't', certState: readyCert()))['ok'], isTrue);
    expect(
      (await client.updateProfile(bearerToken: 't', certState: readyCert(), payload: {'a': 1}))['ok'],
      isTrue,
    );
    expect(headers['GET /statements'], isNotNull);
    expect(headers['GET /profile'], isNotNull);
    expect(headers['PUT /profile'], isNull);
    expect(EnvelopeMessage.fromHeader(headers['GET /statements']!).mlkemCiphertext, hasLength(1088));
  });

  test('returns an empty map when the response has no body', () async {
    final server = await serve((request) async {
      await openRequest(request);
      request.response.statusCode = 200;
      await request.response.close();
    });
    addTearDown(() => server.close(force: true));

    final response = await clientFor(server).getStatements(bearerToken: 't', certState: readyCert());

    expect(response, isEmpty);
  });

  test('an enveloped response with an empty plaintext is an empty map', () async {
    final server = await serve((request) async {
      final (_, responseKey) = await openRequest(request);
      final message = envelopeServer.sealResponse(
        responseKey: responseKey,
        kid: envelopeServer.keySet.kid,
        aad: 'GET /statements',
        body: '',
      );
      request.response.statusCode = 200;
      request.response.headers.contentType = ContentType.parse(EnvelopeMessage.mediaType);
      request.response.write(jsonEncode(message.toJson()));
      await request.response.close();
    });
    addTearDown(() => server.close(force: true));

    expect(await clientFor(server).getStatements(bearerToken: 't', certState: readyCert()), isEmpty);
  });

  test('maps an enveloped backend problem to a BankingHttpProblemException', () async {
    final server = await serve(
      (request) => respondEnveloped(request, 422, {'errorCode': 'pix_error'}, contentType: 'application/problem+json'),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).getStatements(bearerToken: 't', certState: readyCert()),
      throwsA(
        isA<BankingHttpProblemException>()
            .having((e) => e.statusCode, 'statusCode', 422)
            .having((e) => e.problem['errorCode'], 'errorCode', 'pix_error'),
      ),
    );
  });

  test('accepts a plaintext problem produced before the envelope filter', () async {
    final server = await serve((request) async => respondJson(request, 401, {'errorCode': 'auth_invalid_token'}));
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).getStatements(bearerToken: 't', certState: readyCert()),
      throwsA(
        isA<BankingHttpProblemException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.problem['errorCode'], 'errorCode', 'auth_invalid_token'),
      ),
    );
  });

  test('refuses a plaintext success response', () async {
    final server = await serve((request) async => respondJson(request, 200, {'ok': true}));
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).getStatements(bearerToken: 't', certState: readyCert()),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('not an envelope'))),
    );
  });

  test('refuses a response envelope it cannot open', () async {
    final server = await serve((request) async {
      await openRequest(request);
      request.response.statusCode = 200;
      request.response.headers.contentType = ContentType.parse(EnvelopeMessage.mediaType);
      request.response.write(jsonEncode({'v': 1, 'kid': 'other', 'nonce': base64.encode(Uint8List(12)), 'ciphertext': base64.encode(Uint8List(16))}));
      await request.response.close();
    });
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).getStatements(bearerToken: 't', certState: readyCert()),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('key id mismatch'))),
    );
  });

  test('rejects a request when the certificate, the key set or the signing key is not ready', () async {
    final client = BankingClient(
      gatewayBaseUrl: Uri.parse('http://127.0.0.1:1'),
      trustedCaBytes: const <int>[1],
      secureContextFactory: PlainSecureContextFactory(),
    );

    for (final state in [
      CertState.missing(),
      readyCert(expiresAt: DateTime.now().toUtc().subtract(const Duration(hours: 1))),
      readyCert(withEnvelope: false),
      readyCert(withSigningKey: false),
    ]) {
      await expectLater(
        client.getStatements(bearerToken: 't', certState: state),
        throwsA(isA<BankingClientCertificateException>()),
      );
    }
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
