import 'dart:convert';

import '../../core/tls/cert_state.dart';
import 'csr_service.dart';
import 'keypair_service.dart';

abstract interface class BootstrapGateway {
  Future<OtkIssueResult> issueOtk({
    required String bearerToken,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
  });

  Future<CertificateEnrollmentResult> submitCsr({
    required String bearerToken,
    required String otk,
    required String csrPem,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  });
}

class OtkIssueResult {
  const OtkIssueResult({
    required this.otk,
    required this.expiresAt,
  });

  final String otk;
  final DateTime expiresAt;
}

class CertificateEnrollmentResult {
  const CertificateEnrollmentResult({
    required this.certificateChainBytes,
    required this.expiresAt,
  });

  final List<int> certificateChainBytes;
  final DateTime expiresAt;
}

class BootstrapProblem implements Exception {
  const BootstrapProblem(this.errorCode);

  final String errorCode;
}

class EnrollmentOrchestrator {
  const EnrollmentOrchestrator({
    required BootstrapGateway bootstrapGateway,
    KeypairService? keypairService,
    CsrService? csrService,
  })  : _bootstrapGateway = bootstrapGateway,
        _keypairService = keypairService,
        _csrService = csrService;

  final BootstrapGateway _bootstrapGateway;
  final KeypairService? _keypairService;
  final CsrService? _csrService;

  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  }) async {
    try {
      final keys = _keypairService ?? KeypairService();
      final keyPair = keys.generateRsaKeyPair();
      final csrPem = (_csrService ?? CsrService()).generatePem(
        input: CsrInput(
          oauth2Subject: oauth2Subject,
          appInstanceId: appInstanceId,
          deviceId: deviceId,
          certificateProfile: certificateProfile,
          environment: environment,
        ),
        keyPair: keyPair,
      );

      final otkResult = await _bootstrapGateway.issueOtk(
        bearerToken: bearerToken,
        appInstanceId: appInstanceId,
        deviceId: deviceId,
        certificateProfile: certificateProfile,
      );

      final enrollmentResult = await _bootstrapGateway.submitCsr(
        bearerToken: bearerToken,
        otk: otkResult.otk,
        csrPem: csrPem,
        appInstanceId: appInstanceId,
        deviceId: deviceId,
        certificateProfile: certificateProfile,
        environment: environment,
      );

      return CertState.ready(
        certificateChainBytes: enrollmentResult.certificateChainBytes,
        privateKeyBytes: utf8.encode(keys.encodePrivateKeyPem(keyPair.privateKey)),
        expiresAt: enrollmentResult.expiresAt,
        certificateProfile: certificateProfile,
        environment: environment,
        appInstanceId: appInstanceId,
        deviceId: deviceId,
      );
    } on BootstrapProblem catch (problem) {
      return switch (problem.errorCode) {
        'otk_expired' => CertState.otkExpired(),
        'otk_replayed' => CertState.otkReplayed(),
        'csr_invalid' || 'private_key_rejected' || 'certificate_profile_mismatch' => CertState.csrRejected(),
        _ => CertState.csrRejected(),
      };
    }
  }
}
