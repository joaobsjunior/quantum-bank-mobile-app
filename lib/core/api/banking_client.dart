import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../pqc/hybrid_envelope.dart';
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

/// mTLS banking client. Every request body is sealed in the hybrid
/// application envelope (ML-KEM-768 + X25519, AES-256-GCM) keyed to the
/// backend's verified key set, and every response is opened with the key
/// derived from the same secret; requests without a body carry the
/// encapsulation in the `X-Quantum-Envelope` header. The gateway only ever
/// sees ciphertext, whatever the TLS tier negotiated with the device.
class BankingClient implements BankingGatewayClient {
  BankingClient({
    required this.gatewayBaseUrl,
    required this.trustedCaBytes,
    SecureContextFactory? secureContextFactory,
    HybridEnvelope? envelope,
    DateTime Function()? clock,
  }) : _secureContextFactory = secureContextFactory ?? SecureContextFactory(),
       _envelope = envelope ?? HybridEnvelope(),
       _clock = clock ?? (() => DateTime.now().toUtc());

  final Uri gatewayBaseUrl;
  final List<int> trustedCaBytes;
  final SecureContextFactory _secureContextFactory;
  final HybridEnvelope _envelope;
  final DateTime Function() _clock;

  @override
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

  @override
  Future<Map<String, dynamic>> getStatements({
    required String bearerToken,
    required CertState certState,
  }) => _sendJson(
    'GET',
    '/statements',
    bearerToken: bearerToken,
    certState: certState,
  );

  @override
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
    final ready = _readyStateFor(certState);
    final httpClient = HttpClient(context: _secureContextFor(ready));
    final aad = '$method $path';
    final sealed = await _envelope.seal(
      keySet: ready.envelopeKeySet!,
      aad: aad,
      plaintext: body == null
          ? null
          : Uint8List.fromList(utf8.encode(jsonEncode(body))),
      now: _clock(),
    );

    final request = await httpClient.openUrl(
      method,
      gatewayBaseUrl.resolve(path),
    );
    request.headers.set(HttpHeaders.authorizationHeader, 'Bearer $bearerToken');
    if (body != null) {
      request.headers.contentType = ContentType.parse(EnvelopeMessage.mediaType);
      request.write(jsonEncode(sealed.message.toJson()));
    } else {
      request.headers.set(
        EnvelopeMessage.requestHeader,
        sealed.message.toHeaderValue(),
      );
    }

    final response = await request.close();
    final responseBytes = await response.fold<List<int>>(
      <int>[],
      (buffer, chunk) => buffer..addAll(chunk),
    );
    final decoded = _decodeResponse(response, responseBytes, sealed.session);
    if (response.statusCode >= 400) {
      throw BankingHttpProblemException(
        statusCode: response.statusCode,
        problem: decoded,
      );
    }
    return decoded;
  }

  /// Opens an envelope response, or parses a plaintext problem produced
  /// before the backend's envelope filter (the gateway or the resource
  /// server). A plaintext success body is never accepted: the backend always
  /// answers an enveloped request with an envelope.
  Map<String, dynamic> _decodeResponse(
    HttpClientResponse response,
    List<int> bytes,
    EnvelopeSession session,
  ) {
    if (bytes.isEmpty) {
      return <String, dynamic>{};
    }
    final contentType = response.headers.contentType?.mimeType;
    if (contentType == EnvelopeMessage.mediaType) {
      final message = EnvelopeMessage.fromJson(
        jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>,
      );
      final plaintext = session.openResponse(message);
      return plaintext.isEmpty
          ? <String, dynamic>{}
          : jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
    }
    if (response.statusCode >= 400) {
      return jsonDecode(utf8.decode(bytes)) as Map<String, dynamic>;
    }
    throw const EnvelopeException('banking response is not an envelope');
  }

  ReadyCertState _readyStateFor(CertState certState) {
    if (certState is! ReadyCertState || !certState.isEnvelopeReadyAt(_clock())) {
      throw BankingClientCertificateException(certState.name);
    }
    return certState;
  }

  SecurityContext _secureContextFor(ReadyCertState certState) =>
      _secureContextFactory.build(
        trustedCaBytes: trustedCaBytes,
        certificateChainBytes: certState.certificateChainBytes,
        privateKeyBytes: certState.privateKeyBytes,
      );
}
