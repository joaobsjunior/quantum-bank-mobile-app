import 'dart:convert';
import 'dart:io';

import '../tls/cert_state.dart';
import '../tls/secure_context_factory.dart';

abstract interface class BankingGatewayClient {
  Future<Map<String, dynamic>> createPixTransfer({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  });

  Future<Map<String, dynamic>> getStatements({
    required String bearerToken,
    required CertState certState,
  });

  Future<Map<String, dynamic>> getProfile({
    required String bearerToken,
    required CertState certState,
  });

  Future<Map<String, dynamic>> updateProfile({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  });
}

class BankingClientCertificateException implements Exception {
  const BankingClientCertificateException(this.stateName);

  final String stateName;

  @override
  String toString() => 'BankingClientCertificateException: $stateName';
}

class BankingHttpProblemException implements Exception {
  const BankingHttpProblemException({
    required this.statusCode,
    required this.problem,
  });

  final int statusCode;
  final Map<String, dynamic> problem;

  @override
  String toString() => 'BankingHttpProblemException($statusCode): $problem';
}

class BankingClient implements BankingGatewayClient {
  BankingClient({
    required this.gatewayBaseUrl,
    required this.trustedCaBytes,
    SecureContextFactory? secureContextFactory,
  }) : _secureContextFactory = secureContextFactory ?? SecureContextFactory();

  final Uri gatewayBaseUrl;
  final List<int> trustedCaBytes;
  final SecureContextFactory _secureContextFactory;

  Future<Map<String, dynamic>> createPixTransfer({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) => _sendJson(
    'POST',
    '/pix/transfers',
    bearerToken: bearerToken,
    certState: certState,
    body: payload,
  );

  Future<Map<String, dynamic>> getStatements({
    required String bearerToken,
    required CertState certState,
  }) => _sendJson(
    'GET',
    '/statements',
    bearerToken: bearerToken,
    certState: certState,
  );

  Future<Map<String, dynamic>> getProfile({
    required String bearerToken,
    required CertState certState,
  }) => _sendJson(
    'GET',
    '/profile',
    bearerToken: bearerToken,
    certState: certState,
  );

  @override
  Future<Map<String, dynamic>> updateProfile({
    required String bearerToken,
    required CertState certState,
    required Map<String, Object?> payload,
  }) => _sendJson(
    'PUT',
    '/profile',
    bearerToken: bearerToken,
    certState: certState,
    body: payload,
  );

  Future<Map<String, dynamic>> _sendJson(
    String method,
    String path, {
    required String bearerToken,
    required CertState certState,
    Map<String, Object?>? body,
  }) async {
    final httpClient = _httpClientFor(certState);
    final request = await httpClient.openUrl(
      method,
      gatewayBaseUrl.resolve(path),
    );
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $bearerToken');

    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(body));
    }

    final response = await request.close();
    final responseBody = await utf8.decodeStream(response);
    final decoded = responseBody.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(responseBody) as Map<String, dynamic>;
    if (response.statusCode >= 400) {
      throw BankingHttpProblemException(
        statusCode: response.statusCode,
        problem: decoded,
      );
    }

    return decoded;
  }

  HttpClient _httpClientFor(CertState certState) {
    if (certState is! ReadyCertState ||
        !certState.isReadyAt(DateTime.now().toUtc())) {
      throw BankingClientCertificateException(certState.name);
    }

    final secureContext = _secureContextFactory.build(
      trustedCaBytes: trustedCaBytes,
      certificateChainBytes: certState.certificateChainBytes,
      privateKeyBytes: certState.privateKeyBytes,
    );

    return HttpClient(context: secureContext);
  }
}
