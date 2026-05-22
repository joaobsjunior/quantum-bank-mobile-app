import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/banking_client.dart';
import 'package:quantum_bank_mobile/core/config/runtime_config.dart';
import 'package:quantum_bank_mobile/features/auth/keycloak_auth_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/bootstrap_client.dart';
import 'package:quantum_bank_mobile/features/bootstrap/enrollment_orchestrator.dart';

void main() {
  test(
    'live local client flow reaches Keycloak, KrakenD bootstrap, PKI, and banking KrakenD',
    () async {
      if (Platform.environment['QUANTUM_BANK_LIVE_TESTS'] != 'true') {
        markTestSkipped(
          'Set QUANTUM_BANK_LIVE_TESTS=true with the Docker stack running.',
        );
        return;
      }

      final config = RuntimeConfig.localDefaults(
        appInstanceId: 'app-live-test-${DateTime.now().millisecondsSinceEpoch}',
        deviceId: 'device-live-test',
      );
      final trustedCaBytes = await File(
        '../pki/local-ca/trust/root-ca.crt',
      ).readAsBytes();
      final authClient = KeycloakAuthClient(
        tokenUrl: config.keycloakTokenUrl,
        clientId: config.keycloakClientId,
        username: config.localUsername,
        password: config.localPassword,
      );
      final session = await authClient.authenticate();
      final enrollment =
          await EnrollmentOrchestrator(
            bootstrapGateway: BootstrapClient(
              baseUrl: config.gatewayBootstrapBaseUrl,
              trustedCaBytes: trustedCaBytes,
            ),
          ).enroll(
            bearerToken: session.accessToken,
            oauth2Subject: session.subject,
            appInstanceId: config.appInstanceId,
            deviceId: config.deviceId,
            certificateProfile: config.certificateProfile,
            environment: config.environment,
          );

      final banking = BankingClient(
        gatewayBaseUrl: config.gatewayBaseUrl,
        trustedCaBytes: trustedCaBytes,
      );
      final statements = await banking.getStatements(
        bearerToken: session.accessToken,
        certState: enrollment,
      );
      final profile = await banking.getProfile(
        bearerToken: session.accessToken,
        certState: enrollment,
      );
      final updatedProfile = await banking.updateProfile(
        bearerToken: session.accessToken,
        certState: enrollment,
        payload: const {
          'fullName': 'Alice Quantum Live Test',
          'email': 'alice.live@quantumbank.local',
          'phone': '+55 71 90000-0701',
          'address': 'Rua Live Test, 701 - Salvador, BA',
        },
      );
      final pix = await banking.createPixTransfer(
        bearerToken: session.accessToken,
        certState: enrollment,
        payload: const {
          'amount': 25.3,
          'recipientKey': 'recipient@example.com',
          'description': 'Flutter live runtime test',
          'scenario': 'SUCCESS',
        },
      );

      expect(statements['entries'], isA<List<dynamic>>());
      expect(statements['entries'] as List<dynamic>, isNotEmpty);
      expect(profile['fullName'], equals('Alice Quantum'));
      expect(updatedProfile['fullName'], equals('Alice Quantum Live Test'));
      expect(pix['status'], equals('COMPLETED'));
    },
  );
}
