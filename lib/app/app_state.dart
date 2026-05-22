import 'package:flutter/foundation.dart';

import '../core/tls/cert_state.dart';

class QuantumBankAppState extends ChangeNotifier {
  bool authenticated = false;
  CertState certificateState = CertState.missing();

  bool get certificateReady => certificateState is ReadyCertState;

  bool get protectedReady => authenticated && certificateReady;

  void authenticate() {
    authenticated = true;
    notifyListeners();
  }

  void markCertificateReady() {
    certificateState = CertState.ready(
      certificateChainBytes: const <int>[1, 2, 3],
      privateKeyBytes: const <int>[4, 5, 6],
      expiresAt: DateTime.now().toUtc().add(const Duration(hours: 1)),
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
    );
    notifyListeners();
  }
}
