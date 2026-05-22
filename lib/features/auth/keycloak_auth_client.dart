import 'dart:convert';
import 'dart:io';

import 'auth_client.dart';

class KeycloakAuthClient implements Authenticator {
  KeycloakAuthClient({
    required this.tokenUrl,
    required this.clientId,
    required this.username,
    required this.password,
    this.clientSecret = '',
    HttpClient? httpClient,
  }) : _httpClient = httpClient ?? HttpClient();

  final Uri tokenUrl;
  final String clientId;
  final String username;
  final String password;
  final String clientSecret;
  final HttpClient _httpClient;

  @override
  Future<AuthSession> authenticate() async {
    Object? lastError;
    for (var attempt = 0; attempt < 3; attempt += 1) {
      try {
        return await _authenticateOnce();
      } on SocketException catch (error) {
        lastError = error;
        if (attempt == 2) {
          rethrow;
        }
        await Future<void>.delayed(const Duration(milliseconds: 350));
      }
    }

    throw AuthException(statusCode: 0, message: lastError.toString());
  }

  Future<AuthSession> _authenticateOnce() async {
    final request = await _httpClient.postUrl(tokenUrl);
    request.headers.contentType = ContentType(
      'application',
      'x-www-form-urlencoded',
      charset: 'utf-8',
    );

    final form = <String, String>{
      'grant_type': 'password',
      'client_id': clientId,
      'username': username,
      'password': password,
    };
    if (clientSecret.isNotEmpty) {
      form['client_secret'] = clientSecret;
    }

    request.write(Uri(queryParameters: form).query);

    final response = await request.close();
    final responseBody = await utf8.decodeStream(response);
    final decoded = responseBody.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(responseBody) as Map<String, dynamic>;
    if (response.statusCode >= 400) {
      throw AuthException(
        statusCode: response.statusCode,
        message:
            decoded['error_description'] as String? ??
            decoded['error'] as String? ??
            'authentication_failed',
      );
    }

    final accessToken = decoded['access_token'] as String?;
    if (accessToken == null || accessToken.isEmpty) {
      throw const AuthException(statusCode: 0, message: 'missing_access_token');
    }

    final tokenPayload = _decodeJwtPayload(accessToken);
    final subject =
        tokenPayload['sub'] as String? ??
        tokenPayload['preferred_username'] as String? ??
        tokenPayload['azp'] as String?;
    if (subject == null || subject.isEmpty) {
      throw const AuthException(
        statusCode: 0,
        message: 'missing_token_subject',
      );
    }

    final expiresIn = decoded['expires_in'] is int
        ? decoded['expires_in'] as int
        : 300;
    final scopeText =
        decoded['scope'] as String? ?? tokenPayload['scope'] as String? ?? '';
    return AuthSession(
      accessToken: accessToken,
      subject: subject,
      expiresAt: DateTime.now().toUtc().add(Duration(seconds: expiresIn)),
      scopes: scopeText
          .split(' ')
          .where((scope) => scope.isNotEmpty)
          .toList(growable: false),
    );
  }

  Map<String, dynamic> _decodeJwtPayload(String token) {
    final parts = token.split('.');
    if (parts.length < 2) {
      throw const AuthException(statusCode: 0, message: 'invalid_access_token');
    }

    final normalized = base64Url.normalize(parts[1]);
    return jsonDecode(utf8.decode(base64Url.decode(normalized)))
        as Map<String, dynamic>;
  }
}
