import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart';

class CsrInput {
  const CsrInput({
    required this.oauth2Subject,
    required this.appInstanceId,
    required this.deviceId,
    required this.certificateProfile,
    required this.environment,
  });

  final String oauth2Subject;
  final String appInstanceId;
  final String deviceId;
  final String certificateProfile;
  final String environment;

  Map<String, String> get distinguishedName => {
        'CN': oauth2Subject,
        'O': 'Quantum Bank',
        'OU': certificateProfile,
        'ST': appInstanceId,
        'SN': deviceId,
        'L': environment,
      };

  List<String> get subjectAlternativeNames => [
        'urn:quantum-bank:subject:$oauth2Subject',
        'urn:quantum-bank:app-instance:$appInstanceId',
        'urn:quantum-bank:device:$deviceId',
        'urn:quantum-bank:environment:$environment',
      ];
}

class CsrService {
  String generatePem({
    required CsrInput input,
    required AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair,
  }) =>
      X509Utils.generateRsaCsrPem(
        input.distinguishedName,
        keyPair.privateKey,
        keyPair.publicKey,
        san: input.subjectAlternativeNames,
      );
}
