import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';

import 'pqc_asn1.dart';

/// Raised when a certificate cannot be parsed or a chain does not verify.
class CertificateVerificationException implements Exception {
  const CertificateVerificationException(this.message);

  final String message;

  @override
  String toString() => 'CertificateVerificationException: $message';
}

/// The parts of an X.509 certificate the app needs to verify an ML-DSA chain
/// in pure Dart, independent of the platform TLS stack: the DER of the
/// `tbsCertificate` (the signed bytes), issuer and subject names (compared
/// byte for byte), validity, the subject public key and the CA flag.
class MlDsaCertificate {
  const MlDsaCertificate({
    required this.tbsCertificate,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.publicKeyLevel,
    required this.publicKey,
    required this.signatureLevel,
    required this.signature,
    required this.isCa,
    required this.commonName,
  });

  static const String _basicConstraintsOid = '2.5.29.19';
  static const String _commonNameOid = '2.5.4.3';
  static const int _extensionsTag = 0xA3;

  final Uint8List tbsCertificate;
  final Uint8List issuer;
  final Uint8List subject;
  final DateTime notBefore;
  final DateTime notAfter;
  final MlDsaLevel publicKeyLevel;
  final Uint8List publicKey;
  final MlDsaLevel signatureLevel;
  final Uint8List signature;
  final bool isCa;
  final String? commonName;

  factory MlDsaCertificate.fromPem(String pem) =>
      MlDsaCertificate.fromDer(PqcAsn1.derFromPem(pem, 'CERTIFICATE'));

  /// Parses one DER certificate. Only ML-DSA keys and signatures are
  /// accepted: an RSA, ECDSA or EdDSA certificate in the signer chain is a
  /// verification failure, not a fallback.
  factory MlDsaCertificate.fromDer(Uint8List der) {
    try {
      final certificate = ASN1Parser(der).nextObject() as ASN1Sequence;
      final tbs = certificate.elements![0] as ASN1Sequence;
      final signatureAlgorithm = certificate.elements![1] as ASN1Sequence;
      final signature = certificate.elements![2] as ASN1BitString;

      final fields = tbs.elements!;
      // version [0] EXPLICIT is optional; ML-DSA certificates are always v3.
      final offset = fields[0].tag == 0xA0 ? 1 : 0;
      final issuer = fields[offset + 2];
      final validity = fields[offset + 3] as ASN1Sequence;
      final subject = fields[offset + 4];
      final spki = fields[offset + 5] as ASN1Sequence;
      final spkiAlgorithm = spki.elements![0] as ASN1Sequence;
      final spkiKey = spki.elements![1] as ASN1BitString;

      var isCa = false;
      for (final field in fields.skip(offset + 6)) {
        if (field.tag == _extensionsTag) {
          isCa = _basicConstraintsCa(field.valueBytes!);
        }
      }

      return MlDsaCertificate(
        tbsCertificate: tbs.encodedBytes!,
        issuer: issuer.encodedBytes!,
        subject: subject.encodedBytes!,
        notBefore: timeOf(validity.elements![0]),
        notAfter: timeOf(validity.elements![1]),
        publicKeyLevel: _level(spkiAlgorithm),
        publicKey: Uint8List.fromList(spkiKey.stringValues!),
        signatureLevel: _level(signatureAlgorithm),
        signature: Uint8List.fromList(signature.stringValues!),
        isCa: isCa,
        commonName: _commonName(subject as ASN1Sequence),
      );
    } on CertificateVerificationException {
      rethrow;
    } catch (error) {
      throw CertificateVerificationException('malformed certificate: $error');
    }
  }

  /// True when [issuerCertificate]'s key verifies this certificate's
  /// signature over its `tbsCertificate` (pure ML-DSA, empty context, as
  /// RFC 9881 specifies for X.509).
  bool isSignedBy(MlDsaCertificate issuerCertificate) =>
      MlDsa.verify(
        issuerCertificate.publicKey,
        tbsCertificate,
        signature,
        signatureLevel.params,
      ) &&
      issuerCertificate.publicKeyLevel == signatureLevel;

  bool isValidAt(DateTime now) =>
      !now.isBefore(notBefore) && now.isBefore(notAfter);

  bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return false;
    }
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  bool issuedBy(MlDsaCertificate candidate) =>
      _sameBytes(issuer, candidate.subject);

  static MlDsaLevel _level(ASN1Sequence algorithmIdentifier) {
    final oid =
        (algorithmIdentifier.elements![0] as ASN1ObjectIdentifier)
            .objectIdentifierAsString;
    for (final level in MlDsaLevel.values) {
      if (level.oid == oid) {
        return level;
      }
    }
    throw CertificateVerificationException(
      'certificate algorithm is not ML-DSA-65/87: $oid',
    );
  }

  /// `Time ::= CHOICE { utcTime, generalTime }` (RFC 5280); anything else is malformed.
  @visibleForTesting
  static DateTime timeOf(ASN1Object object) {
    if (object is ASN1UtcTime) {
      return object.time!.toUtc();
    }
    if (object is ASN1GeneralizedTime) {
      return object.dateTimeValue!.toUtc();
    }
    throw const CertificateVerificationException('invalid validity time');
  }

  static bool _basicConstraintsCa(Uint8List extensionsDer) {
    final extensions = ASN1Parser(extensionsDer).nextObject() as ASN1Sequence;
    for (final extension in extensions.elements!.cast<ASN1Sequence>()) {
      final oid = (extension.elements![0] as ASN1ObjectIdentifier)
          .objectIdentifierAsString;
      if (oid != _basicConstraintsOid) {
        continue;
      }
      final value = extension.elements!.last as ASN1OctetString;
      final constraints = ASN1Parser(value.valueBytes!).nextObject() as ASN1Sequence;
      final first = constraints.elements!.firstOrNull;
      return first is ASN1Boolean && first.boolValue == true;
    }
    return false;
  }

  static String? _commonName(ASN1Sequence name) {
    for (final rdn in name.elements!.cast<ASN1Set>()) {
      for (final attribute in rdn.elements!.cast<ASN1Sequence>()) {
        final oid = (attribute.elements![0] as ASN1ObjectIdentifier)
            .objectIdentifierAsString;
        if (oid == _commonNameOid) {
          final value = attribute.elements![1];
          if (value is ASN1UTF8String) {
            return value.utf8StringValue;
          }
          if (value is ASN1PrintableString) {
            return value.stringValue;
          }
        }
      }
    }
    return null;
  }
}

/// Verifies an ML-DSA certificate chain against one trust anchor, the way a
/// TLS stack would, but in Dart: signatures, issuer/subject linkage, validity
/// windows and the CA flag on every issuer. Used for the envelope key set
/// signer so the trust decision never depends on `dart:io`.
class MlDsaChainVerifier {
  const MlDsaChainVerifier({required this.trustAnchor});

  final MlDsaCertificate trustAnchor;

  /// [chain] is leaf first, without the root. Returns the verified leaf.
  MlDsaCertificate verify(List<MlDsaCertificate> chain, {required DateTime now}) {
    if (chain.isEmpty) {
      throw const CertificateVerificationException('empty certificate chain');
    }
    if (!trustAnchor.isCa) {
      throw const CertificateVerificationException('trust anchor is not a CA');
    }
    for (var i = 0; i < chain.length; i++) {
      final certificate = chain[i];
      final issuer = i + 1 < chain.length ? chain[i + 1] : trustAnchor;
      if (!certificate.isValidAt(now)) {
        throw CertificateVerificationException(
          'certificate ${certificate.commonName} is outside its validity window',
        );
      }
      if (!issuer.isCa) {
        throw CertificateVerificationException(
          'issuer ${issuer.commonName} is not a CA',
        );
      }
      if (!certificate.issuedBy(issuer)) {
        throw CertificateVerificationException(
          'certificate ${certificate.commonName} is not issued by ${issuer.commonName}',
        );
      }
      if (!certificate.isSignedBy(issuer)) {
        throw CertificateVerificationException(
          'ML-DSA signature of ${certificate.commonName} does not verify',
        );
      }
    }
    return chain.first;
  }
}
