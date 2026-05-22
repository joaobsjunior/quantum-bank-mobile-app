import 'package:flutter/foundation.dart';

import '../core/config/runtime_config.dart';
import '../core/tls/cert_state.dart';
import '../features/auth/auth_client.dart';
import '../features/bootstrap/enrollment_orchestrator.dart';

class QuantumBankAppState extends ChangeNotifier {
  QuantumBankAppState({
    required Authenticator authenticator,
    required CertificateEnrollment certificateEnrollment,
    required RuntimeConfig runtimeConfig,
  }) : _authenticator = authenticator,
       _certificateEnrollment = certificateEnrollment,
       _runtimeConfig = runtimeConfig;

  final Authenticator _authenticator;
  final CertificateEnrollment _certificateEnrollment;
  final RuntimeConfig _runtimeConfig;

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
