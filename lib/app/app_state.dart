import 'package:flutter/foundation.dart';

import '../core/config/runtime_config.dart';
import '../core/tls/cert_state.dart';
import '../core/tls/pqc_tls_support.dart';
import '../features/auth/auth_client.dart';
import '../features/bootstrap/enrollment_orchestrator.dart';

class QuantumBankAppState extends ChangeNotifier {
  QuantumBankAppState({
    required Authenticator authenticator,
    required CertificateEnrollment certificateEnrollment,
    required RuntimeConfig runtimeConfig,
    PqcTransportStatus pqcTransport = const PqcTransportStatus.supported(),
  }) : _authenticator = authenticator,
       _certificateEnrollment = certificateEnrollment,
       _runtimeConfig = runtimeConfig,
       pqcTransport = pqcTransport;

  final Authenticator _authenticator;
  final CertificateEnrollment _certificateEnrollment;
  final RuntimeConfig _runtimeConfig;

  /// Whether the platform TLS stack can drive the post-quantum (ML-DSA)
  /// transport. When it can, the device enrolls an ML-DSA-65 identity and
  /// verifies the listeners' ML-DSA certificates; when it cannot, the device
  /// runs in compatibility mode with an ECDSA P-256 identity under the PKI's
  /// compatibility chain. Both are PKI-issued, mutually authenticated
  /// transports; the mode is shown to the user, never hidden.
  final PqcTransportStatus pqcTransport;

  bool get pqcTransportSupported => pqcTransport.supported;

  TransportMode get transportMode => pqcTransport.mode;

  /// User-facing description of the negotiated transport class.
  String get transportLabel => switch (transportMode) {
    TransportMode.postQuantum =>
      'Transporte pós-quântico (ML-DSA-65 + X25519MLKEM768).',
    TransportMode.compatibility =>
      'Transporte em modo de compatibilidade (ECDSA P-256): '
          'ML-DSA indisponível na pilha TLS deste dispositivo.',
  };

  bool authenticated = false;
  bool authenticating = false;
  bool enrollingCertificate = false;
  String? lastError;
  AuthSession? authSession;
  CertState certificateState = CertState.missing();

  bool get certificateReady => certificateState is ReadyCertState;

  bool get protectedReady => authenticated && certificateReady;

  Future<void> authenticate() async {
    authenticating = true;
    lastError = null;
    notifyListeners();

    try {
      authSession = await _authenticator.authenticate();
      authenticated = true;
    } catch (error) {
      authenticated = false;
      authSession = null;
      lastError = error.toString();
    } finally {
      authenticating = false;
      notifyListeners();
    }
  }

  Future<void> markCertificateReady() async {
    final session = authSession;
    if (session == null) {
      lastError = 'Authenticate before activating the device certificate.';
      notifyListeners();
      return;
    }

    enrollingCertificate = true;
    lastError = null;
    notifyListeners();

    try {
      certificateState = await _certificateEnrollment.enroll(
        bearerToken: session.accessToken,
        oauth2Subject: session.subject,
        appInstanceId: _runtimeConfig.appInstanceId,
        deviceId: _runtimeConfig.deviceId,
        certificateProfile: _runtimeConfig.certificateProfile,
        environment: _runtimeConfig.environment,
      );
      if (certificateState is! ReadyCertState) {
        lastError = 'Certificate enrollment failed: ${certificateState.name}';
      }
    } catch (error) {
      certificateState = CertState.csrRejected();
      lastError = error.toString();
    } finally {
      enrollingCertificate = false;
      notifyListeners();
    }
  }
}
