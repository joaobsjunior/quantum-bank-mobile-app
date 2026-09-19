import '../pqc/hybrid_envelope.dart';
import '../pqc/transaction_signer.dart';

sealed class CertState {
  const CertState(this.name);

  factory CertState.missing() = MissingCertState;
  factory CertState.ready({
    required List<int> certificateChainBytes,
    required List<int> privateKeyBytes,
    required DateTime expiresAt,
    required String certificateProfile,
    required String environment,
    required String appInstanceId,
    required String deviceId,
    EnvelopeKeySet? envelopeKeySet,
    DeviceSigningKey? signingKey,
  }) = ReadyCertState;
  factory CertState.expired() = ExpiredCertState;
  factory CertState.untrusted() = UntrustedCertState;
  factory CertState.csrRejected() = CsrRejectedCertState;
  factory CertState.otkExpired() = OtkExpiredCertState;
  factory CertState.otkReplayed() = OtkReplayedCertState;

  final String name;

  List<int>? get certificateChainBytes => null;
  List<int>? get privateKeyBytes => null;
  DateTime? get expiresAt => null;
  String? get certificateProfile => null;
  String? get environment => null;
  String? get appInstanceId => null;
  String? get deviceId => null;

  /// Verified backend envelope keys (feature 012); null until enrolled.
  EnvelopeKeySet? get envelopeKeySet => null;

  /// Device ML-DSA-65 signing key registered at enrollment; null until enrolled.
  DeviceSigningKey? get signingKey => null;

  bool isReadyAt(DateTime now) => false;

  /// Whether the protected surface can be called: transport identity valid,
  /// verified envelope key set and signing key present (feature 012).
  bool isEnvelopeReadyAt(DateTime now) => false;
}

final class MissingCertState extends CertState {
  const MissingCertState() : super('missing');
}

final class ReadyCertState extends CertState {
  const ReadyCertState({
    required this.certificateChainBytes,
    required this.privateKeyBytes,
    required this.expiresAt,
    required this.certificateProfile,
    required this.environment,
    required this.appInstanceId,
    required this.deviceId,
    this.envelopeKeySet,
    this.signingKey,
  }) : super('ready');

  @override
  final List<int> certificateChainBytes;
  @override
  final List<int> privateKeyBytes;
  @override
  final DateTime expiresAt;
  @override
  final String certificateProfile;
  @override
  final String environment;
  @override
  final String appInstanceId;
  @override
  final String deviceId;
  @override
  final EnvelopeKeySet? envelopeKeySet;
  @override
  final DeviceSigningKey? signingKey;

  @override
  bool isReadyAt(DateTime now) => now.isBefore(expiresAt);

  /// A banking call needs the transport identity, a valid envelope key set and
  /// the signing key; anything less is not "ready" for the protected surface.
  @override
  bool isEnvelopeReadyAt(DateTime now) =>
      isReadyAt(now) &&
      signingKey != null &&
      (envelopeKeySet?.isValidAt(now) ?? false);
}

final class ExpiredCertState extends CertState {
  const ExpiredCertState() : super('expired');
}

final class UntrustedCertState extends CertState {
  const UntrustedCertState() : super('untrusted');
}

final class CsrRejectedCertState extends CertState {
  const CsrRejectedCertState() : super('csrRejected');
}

final class OtkExpiredCertState extends CertState {
  const OtkExpiredCertState() : super('otkExpired');
}

final class OtkReplayedCertState extends CertState {
  const OtkReplayedCertState() : super('otkReplayed');
}
