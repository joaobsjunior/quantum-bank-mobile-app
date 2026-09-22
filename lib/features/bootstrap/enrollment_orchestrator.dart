import 'dart:convert';

import '../../core/pqc/envelope_keys_verifier.dart';
import '../../core/pqc/transaction_signer.dart';
import '../../core/tls/cert_state.dart';
import '../../core/tls/pqc_tls_support.dart';
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
    Map<String, Object?>? signingKey,
  });
}

abstract interface class CertificateEnrollment {
  Future<CertState> enroll({
    required String bearerToken,
    required String oauth2Subject,
    required String appInstanceId,
    required String deviceId,
    required String certificateProfile,
    required String environment,
  });
}

class OtkIssueResult {
  const OtkIssueResult({required this.otk, required this.expiresAt});

  final String otk;
  final DateTime expiresAt;
}

class CertificateEnrollmentResult {
  const CertificateEnrollmentResult({
    required this.certificateChainBytes,
    required this.expiresAt,
    this.envelopeKeys,
  });

  final List<int> certificateChainBytes;
  final DateTime expiresAt;

  /// The `envelopeKeys` object of the CSR response (feature 012), verified by
  /// the orchestrator before it becomes part of the ready state.
  final Map<String, dynamic>? envelopeKeys;
}

class BootstrapProblem implements Exception {
  const BootstrapProblem(this.errorCode);

  final String errorCode;
}

/// Runs the OTK + CSR enrollment with the device identity family that matches
/// the platform's [TransportMode]: an ML-DSA-65 key pair on a post-quantum
/// capable TLS stack, an ECDSA P-256 key pair otherwise. The PKI issues the
/// certificate under the chain of the key family.
///
/// Independently of the transport family, every enrollment also registers an
/// ML-DSA-65 [DeviceSigningKey] (proof of possession over the CSR) and
/// verifies the backend's signed envelope key set with [EnvelopeKeysVerifier];
/// a key set that does not verify leaves the device `untrusted`.
class EnrollmentOrchestrator implements CertificateEnrollment {
  const EnrollmentOrchestrator({
    required BootstrapGateway bootstrapGateway,
    TransportMode transportMode = TransportMode.postQuantum,
    KeypairService? keypairService,
    CsrService? csrService,
    EnvelopeKeysVerifier? envelopeKeysVerifier,
    DeviceSigningKey Function()? signingKeyFactory,
  }) : _bootstrapGateway = bootstrapGateway,
       _transportMode = transportMode,
       _keypairService = keypairService,
       _csrService = csrService,
       _envelopeKeysVerifier = envelopeKeysVerifier,
       _signingKeyFactory = signingKeyFactory;

  final BootstrapGateway _bootstrapGateway;
  final TransportMode _transportMode;
  final KeypairService? _keypairService;
  final CsrService? _csrService;
  final EnvelopeKeysVerifier? _envelopeKeysVerifier;
  final DeviceSigningKey Function()? _signingKeyFactory;

  TransportMode get transportMode => _transportMode;

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
      final keyPair = keys.generateForTransport(_transportMode);
      final csrService = _csrService ?? CsrService();
      final csrInput = CsrInput(
        oauth2Subject: oauth2Subject,
        appInstanceId: appInstanceId,
        deviceId: deviceId,
        certificateProfile: certificateProfile,
        environment: environment,
      );
      final csrDer = csrService.generateDer(input: csrInput, keyPair: keyPair);
      final csrPem = csrService.pemFromDer(csrDer);
      final signingKey = (_signingKeyFactory ?? DeviceSigningKey.generate)();

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
        signingKey: signingKey.registration(csrDer: csrDer),
      );

      final verifier = _envelopeKeysVerifier;
      final envelopeKeys = enrollmentResult.envelopeKeys;
      if (verifier == null || envelopeKeys == null) {
        // Fail closed: a certificate without a trusted envelope key set cannot
        // reach the banking surface, so the device is not enrolled.
        return CertState.untrusted();
      }
      final keySet = verifier.verify(envelopeKeys);

      return CertState.ready(
        certificateChainBytes: enrollmentResult.certificateChainBytes,
        privateKeyBytes: utf8.encode(keys.encodePrivateKeyPem(keyPair)),
        expiresAt: enrollmentResult.expiresAt,
        certificateProfile: certificateProfile,
        environment: environment,
        appInstanceId: appInstanceId,
        deviceId: deviceId,
        envelopeKeySet: keySet,
        signingKey: signingKey,
      );
    } on EnvelopeKeysUntrustedException {
      return CertState.untrusted();
    } on BootstrapProblem catch (problem) {
      return switch (problem.errorCode) {
        'otk_expired' => CertState.otkExpired(),
        'otk_replayed' => CertState.otkReplayed(),
        'csr_invalid' ||
        'private_key_rejected' ||
        'certificate_profile_mismatch' => CertState.csrRejected(),
        _ => CertState.csrRejected(),
      };
    }
  }
}
