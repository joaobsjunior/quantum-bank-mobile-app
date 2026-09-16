import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';

import '../../core/pqc/pqc_asn1.dart';
import 'keypair_service.dart';

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

/// Builds a PKCS#10 certificate signing request whose subject public key and
/// proof-of-possession signature are both ML-DSA (pure signature over the DER
/// `CertificationRequestInfo`, empty context), the encoding OpenSSL >= 3.5 and
/// BouncyCastle verify and the backend's `CsrValidator` requires.
class CsrService {
  static const Map<String, String> _attributeTypeOids = {
    'CN': '2.5.4.3',
    'O': '2.5.4.10',
    'OU': '2.5.4.11',
    'ST': '2.5.4.8',
    'SN': '2.5.4.4',
    'L': '2.5.4.7',
  };
  static const String _extensionRequestOid = '1.2.840.113549.1.9.14';
  static const String _subjectAltNameOid = '2.5.29.17';
  static const int _contextSpecificConstructed0 = 0xA0;
  static const int _generalNameUri = 0x86;

  String generatePem({required CsrInput input, required MlDsaKeyPair keyPair}) =>
      PqcAsn1.pem(PqcAsn1.csrLabel, generateDer(input: input, keyPair: keyPair));

  Uint8List generateDer({required CsrInput input, required MlDsaKeyPair keyPair}) {
    final info = certificationRequestInfo(input: input, keyPair: keyPair);
    final infoDer = info.encode();
    final signature = MlDsa.sign(keyPair.privateKey, infoDer, keyPair.level.params);
    return ASN1Sequence(
      elements: [
        info,
        PqcAsn1.algorithmIdentifier(keyPair.level),
        ASN1BitString(stringValues: signature),
      ],
    ).encode();
  }

  /// `CertificationRequestInfo { version 0, subject, subjectPKInfo, attributes [0] }`.
  ASN1Sequence certificationRequestInfo({
    required CsrInput input,
    required MlDsaKeyPair keyPair,
  }) {
    final subject = ASN1Sequence(
      elements: [
        for (final entry in input.distinguishedName.entries)
          ASN1Set(
            elements: [
              ASN1Sequence(
                elements: [
                  ASN1ObjectIdentifier.fromIdentifierString(
                    _attributeTypeOids[entry.key]!,
                  ),
                  ASN1UTF8String(utf8StringValue: entry.value),
                ],
              ),
            ],
          ),
      ],
    );
    final subjectAltName = ASN1Sequence(
      elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_subjectAltNameOid),
        ASN1OctetString(
          octets: ASN1Sequence(
            elements: [
              for (final name in input.subjectAlternativeNames)
                ASN1IA5String(stringValue: name, tag: _generalNameUri),
            ],
          ).encode(),
        ),
      ],
    );
    final extensionRequest = ASN1Sequence(
      elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_extensionRequestOid),
        ASN1Set(
          elements: [
            ASN1Sequence(elements: [subjectAltName]),
          ],
        ),
      ],
    );
    return ASN1Sequence(
      elements: [
        ASN1Integer(BigInt.zero),
        subject,
        ASN1Sequence(
          elements: [
            PqcAsn1.algorithmIdentifier(keyPair.level),
            ASN1BitString(stringValues: keyPair.publicKey),
          ],
        ),
        ASN1Set(elements: [extensionRequest], tag: _contextSpecificConstructed0),
      ],
    );
  }
}
