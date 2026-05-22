import 'dart:convert';
import 'dart:io';

import 'enrollment_orchestrator.dart';

class BootstrapClient implements BootstrapGateway {
  BootstrapClient({
    required this.baseUrl,
    List<int>? trustedCaBytes,
    HttpClient? httpClient,
  }) : _httpClient = httpClient ?? _buildHttpClient(trustedCaBytes);

  final Uri baseUrl;
  final HttpClient _httpClient;

  static HttpClient _buildHttpClient(List<int>? trustedCaBytes) {
    if (trustedCaBytes == null) {
      return HttpClient();
    }

    final context = SecurityContext(withTrustedRoots: false)
      ..setTrustedCertificatesBytes(trustedCaBytes);
    return HttpClient(context: context);
  }

  @override
  Future<OtkIssueResult> issueOtk({
    required String bearerToken,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
  }) async {
    final response = await _postJson(
      '/auth/otk',
      bearerToken: bearerToken,
      body: {
        'appInstanceId': appInstanceId,
        'deviceId': deviceId,
        'certificateProfile': certificateProfile,
      },
    );

    return OtkIssueResult(
      otk: response['otk'] as String,
      expiresAt: DateTime.parse(response['expiresAt'] as String),
    );
  }

  @override
  Future<CertificateEnrollmentResult> submitCsr({
    required String bearerToken,
    required String otk,
    required String csrPem,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async {
    final response = await _postJson(
      '/auth/csr',
      bearerToken: bearerToken,
      body: {
        'otk': otk,
        'csr': csrPem,
        'appInstanceId': appInstanceId,
        'deviceId': deviceId,
        'certificateProfile': certificateProfile,
        'environment': environment,
      },
    );

    final chain =
        (response['certificateChain'] as List<dynamic>? ??
                <dynamic>[response['certificate'] as String])
            .cast<String>();

    return CertificateEnrollmentResult(
      certificateChainBytes: utf8.encode(chain.join('\n')),
      expiresAt: DateTime.parse(response['expiresAt'] as String),
    );
  }

  Future<Map<String, dynamic>> _postJson(
    String path, {
    required String bearerToken,
    required Map<String, Object?> body,
  }) async {
    final request = await _httpClient.postUrl(baseUrl.resolve(path));
    request.headers
      ..set(HttpHeaders.authorizationHeader, 'Bearer $bearerToken')
      ..contentType = ContentType.json;
    request.write(jsonEncode(body));

    final response = await request.close();
    final responseBody = await utf8.decodeStream(response);
    final decoded = responseBody.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(responseBody) as Map<String, dynamic>;

    if (response.statusCode >= 400) {
      throw BootstrapProblem(
        decoded['errorCode'] as String? ?? 'bootstrap_failed',
      );
    }

    return decoded;
  }
}
