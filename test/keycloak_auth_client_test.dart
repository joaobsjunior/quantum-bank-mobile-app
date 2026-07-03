import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';
import 'package:quantum_bank_mobile/features/auth/keycloak_auth_client.dart';

String jwtWith(Map<String, dynamic> payload) {
  String seg(Map<String, dynamic> m) =>
      base64Url.encode(utf8.encode(jsonEncode(m))).replaceAll('=', '');
  return '${seg({'alg': 'none'})}.${seg(payload)}.signature';
}

Future<HttpServer> serve(void Function(HttpRequest request) handler) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen(handler);
  return server;
}

KeycloakAuthClient clientFor(HttpServer server, {String clientSecret = ''}) =>
    KeycloakAuthClient(
      tokenUrl: Uri.parse('http://127.0.0.1:${server.port}/token'),
      clientId: 'quantum-bank-mobile',
      username: 'alice@quantumbank.local',
      password: 'change-me-local-only',
      clientSecret: clientSecret,
      httpClient: HttpClient(),
    );

void respondJson(HttpRequest request, int status, Map<String, dynamic> body) {
  request.response.statusCode = status;
  request.response.headers.contentType = ContentType.json;
  request.response.write(jsonEncode(body));
  request.response.close();
}

void main() {
  test('returns a session on success and parses subject, scopes and expiry', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {
        'access_token': jwtWith({'sub': 'alice@quantumbank.local'}),
        'expires_in': 120,
        'scope': 'profile:read pix:write',
      }),
    );
    addTearDown(() => server.close(force: true));

    final session = await clientFor(server).authenticate();

    expect(session.subject, equals('alice@quantumbank.local'));
    expect(session.scopes, equals(['profile:read', 'pix:write']));
    expect(session.expiresAt.isAfter(DateTime.now().toUtc()), isTrue);
  });

  test('sends client_secret in the form when configured', () async {
    String? capturedBody;
    final server = await serve((request) async {
      capturedBody = await utf8.decodeStream(request);
      respondJson(request, 200, {
        'access_token': jwtWith({'sub': 'alice@quantumbank.local'}),
        'expires_in': 60,
      });
    });
    addTearDown(() => server.close(force: true));

    await clientFor(server, clientSecret: 'top-secret').authenticate();

    expect(capturedBody, contains('client_secret=top-secret'));
  });

  test('falls back to preferred_username, azp and payload scope', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {
        'access_token': jwtWith({
          'preferred_username': 'bob',
          'azp': 'quantum-bank-mobile',
          'scope': 'statements:read',
        }),
      }),
    );
    addTearDown(() => server.close(force: true));

    final session = await clientFor(server).authenticate();

    expect(session.subject, equals('bob'));
    expect(session.scopes, equals(['statements:read']));
  });

  test('throws AuthException on HTTP error with server description', () async {
    final server = await serve(
      (request) => respondJson(request, 401, {'error_description': 'invalid credentials'}),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(
        isA<AuthException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.message, 'message', 'invalid credentials'),
      ),
    );
  });

  test('throws when the access token is missing', () async {
    final server = await serve((request) => respondJson(request, 200, {}));
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(isA<AuthException>().having((e) => e.message, 'message', 'missing_access_token')),
    );
  });

  test('throws when the access token is not a JWT', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {'access_token': 'not-a-jwt'}),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(isA<AuthException>().having((e) => e.message, 'message', 'invalid_access_token')),
    );
  });

  test('throws when the token has no usable subject claim', () async {
    final server = await serve(
      (request) => respondJson(request, 200, {'access_token': jwtWith({'foo': 'bar'})}),
    );
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(isA<AuthException>().having((e) => e.message, 'message', 'missing_token_subject')),
    );
  });

  test('treats an empty response body as a missing access token', () async {
    final server = await serve((request) {
      request.response.statusCode = 200;
      request.response.close();
    });
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(isA<AuthException>().having((e) => e.message, 'message', 'missing_access_token')),
    );
  });

  test('falls back to the error field when no description is present', () async {
    final server = await serve((request) => respondJson(request, 400, {'error': 'invalid_grant'}));
    addTearDown(() => server.close(force: true));

    await expectLater(
      clientFor(server).authenticate(),
      throwsA(isA<AuthException>().having((e) => e.message, 'message', 'invalid_grant')),
    );
  });

  test('retries and rethrows the socket error when the server is unreachable', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final port = server.port;
    await server.close();

    final client = KeycloakAuthClient(
      tokenUrl: Uri.parse('http://127.0.0.1:$port/token'),
      clientId: 'quantum-bank-mobile',
      username: 'alice@quantumbank.local',
      password: 'change-me-local-only',
      httpClient: HttpClient(),
    );

    await expectLater(client.authenticate(), throwsA(isA<SocketException>()));
  });
}
