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

  bool isReadyAt(DateTime now) => false;
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
  bool isReadyAt(DateTime now) => now.isBefore(expiresAt);
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
