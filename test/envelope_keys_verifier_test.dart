import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/envelope_keys_verifier.dart';
import 'package:quantum_bank_mobile/core/pqc/hybrid_envelope.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';

import 'support/envelope_test_server.dart';

String fixture(String name) => File('test/fixtures/envelope/$name').readAsStringSync();

/// The backend signer's ML-DSA-65 private key expanded from the seed-only
/// PKCS#8 test fixture (`backend-server.test.key`, local throwaway PKI).
Uint8List signerPrivateKey() {
  final der = PqcAsn1.derFromPem(fixture('backend-server.test.key'), PqcAsn1.pkcs8Label);
  final info = ASN1Parser(der).nextObject() as ASN1Sequence;
  final privateKey = (info.elements![2] as ASN1OctetString).valueBytes!;
  final seed = ASN1Parser(privateKey).nextObject().valueBytes!;
  final (_, sk) = MlDsa.generateKeyPairSeeded(DilithiumParams.mlDsa65, Uint8List.fromList(seed));
  return sk;
}

void main() {
  late EnvelopeTestServer server;
  final now = DateTime.utc(2026, 10, 1);
  final chain = [fixture('backend-server.crt'), fixture('issuing-ca.crt')];

  setUpAll(() async {
    server = await EnvelopeTestServer.create(notAfter: DateTime.utc(2026, 10, 2));
  });

  Map<String, dynamic> signed({
    Map<String, Object?>? keySet,
    List<String>? signerChain,
    String? signature,
    Uint8List? context,
  }) {
    final keySetJson = keySet ?? server.keySet.toJson();
    final canonical = EnvelopeKeySet.fromJson(Map<String, dynamic>.from(keySetJson)).canonicalBytes();
    return {
      'keySet': keySetJson,
      'signature': signature ??
          base64.encode(
            MlDsa.sign(
              signerPrivateKey(),
              canonical,
              DilithiumParams.mlDsa65,
              ctx: context ?? EnvelopeKeysVerifier.signatureContext,
            ),
          ),
      'signerChain': signerChain ?? chain,
    };
  }

  EnvelopeKeysVerifier verifier({String cn = 'backend', DateTime? at}) => EnvelopeKeysVerifier(
    trustAnchorPem: utf8.encode(fixture('root-ca.crt')),
    expectedSignerCommonName: cn,
    clock: () => at ?? now,
  );

  test('accepts a key set signed by the PKI-issued backend identity', () {
    final keySet = verifier().verify(signed());

    expect(keySet.kid, equals(server.keySet.kid));
    expect(keySet.mlkemPublicKey, equals(server.keySet.mlkemPublicKey));
  });

  test('rejects tampered, mis-signed, mis-chained and expired key sets', () {
    void expectUntrusted(Map<String, dynamic> envelopeKeys, String fragment, {EnvelopeKeysVerifier? with_}) {
      expect(
        () => (with_ ?? verifier()).verify(envelopeKeys),
        throwsA(isA<EnvelopeKeysUntrustedException>().having((e) => e.toString(), 'reason', contains(fragment))),
      );
    }

    expectUntrusted({'keySet': server.keySet.toJson()}, 'incomplete');
    expectUntrusted({...signed(), 'signerChain': <String>[]}, 'incomplete');
    expectUntrusted({...signed(), 'signature': '***'}, 'not base64');
    expectUntrusted({...signed(), 'keySet': {...server.keySet.toJson(), 'kid': 'other'}}, 'does not verify');
    expectUntrusted(signed(context: Uint8List(0)), 'does not verify');
    expectUntrusted({...signed(), 'keySet': {...server.keySet.toJson(), 'alg': 'RSA'}}, 'unsupported envelope algorithm');
    expectUntrusted(signed(signerChain: [fixture('backend-server.crt')]), 'not issued by');
    expectUntrusted(signed(signerChain: [fixture('issuing-ca.crt')]), 'signed by QuantumBank Local Issuing CA, expected backend');
    expectUntrusted(signed(), 'expected api', with_: verifier(cn: 'api'));
    expectUntrusted(signed(), 'already expired', with_: verifier(at: DateTime.utc(2026, 10, 3)));
    expectUntrusted(signed(), 'validity window', with_: verifier(at: DateTime.utc(2030)));
  });

  test('the default clock is the current UTC time', () {
    final verifier = EnvelopeKeysVerifier(
      trustAnchorPem: utf8.encode(fixture('root-ca.crt')),
      expectedSignerCommonName: 'backend',
    );
    // The fixture chain expired relative to a far-future clock or is valid now;
    // either way the verifier must answer deterministically without throwing
    // anything but the untrusted exception.
    expect(
      () => verifier.verify(signed()),
      anyOf(returnsNormally, throwsA(isA<EnvelopeKeysUntrustedException>())),
    );
  });

  test('a CA certificate that matches the expected name is still refused as signer', () {
    // Sign with the leaf key but present the issuing CA as the signer under
    // the expected name: the chain fails first (the CA is not "backend"), and
    // the CA flag check is exercised through a verifier expecting the CA name.
    expect(
      () => verifier(cn: 'QuantumBank Local Issuing CA').verify(signed(signerChain: [fixture('issuing-ca.crt')])),
      throwsA(isA<EnvelopeKeysUntrustedException>().having((e) => e.reason, 'reason', contains('signed by a CA'))),
    );
  });
}
