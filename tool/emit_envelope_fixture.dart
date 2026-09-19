// Emits cross-implementation evidence for the application envelope
// (feature 012) with the exact code path the app uses:
//
//   dart run tool/emit_envelope_fixture.dart <out_dir>
//
// Writes into <out_dir>:
//   envelope-fixture.json   backend test fixture: backend private keys (PKCS#8),
//                           the signed request envelope, the plaintext, the
//                           device signing key registration and a Pix signature
//   mlkem.key / x25519.key  backend PKCS#8 keys for OpenSSL 3.5 checks
//   mlkem-ct.bin, mlkem-ss.bin, x25519-eph.pub, x25519-ss.bin
//                           the raw ML-KEM ciphertext/shared secret and the
//                           ephemeral X25519 public key/shared secret, for
//                           scripts/verify-pqc-envelope-interop.sh
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as classical;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:quantum_bank_mobile/core/pqc/hybrid_envelope.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
import 'package:quantum_bank_mobile/core/pqc/transaction_signer.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('usage: emit_envelope_fixture.dart OUT_DIR');
    exit(2);
  }
  final outDir = Directory(args[0])..createSync(recursive: true);
  final envelope = HybridEnvelope();

  // Backend-side keys, generated here only to produce the fixture.
  final mlkemSeed = envelope.randomBytes(64);
  final (mlkemPublicKey, mlkemPrivateKey) = PqcKem.kyber768.generateKeyPair(mlkemSeed);
  final x25519 = classical.X25519();
  final x25519Seed = envelope.randomBytes(32);
  final x25519Pair = await x25519.newKeyPairFromSeed(x25519Seed);
  final x25519Public = Uint8List.fromList((await x25519Pair.extractPublicKey()).bytes);
  final keySet = EnvelopeKeySet(
    kid: 'fixture-kid-001',
    mlkemPublicKey: mlkemPublicKey,
    x25519PublicKey: x25519Public,
    notAfter: DateTime.utc(2099, 1, 1),
  );

  // The app side: seal a Pix order signed with the device signing key.
  final signingKey = DeviceSigningKey.fromSeed(envelope.randomBytes(32));
  final csrDer = Uint8List.fromList(utf8.encode('fixture-csr-der'));
  final signer = PixTransactionSigner(
    clock: () => DateTime.utc(2026, 9, 19, 12, 0, 0),
    nonceGenerator: () => '0f9c2d4e-7a1b-4c3d-8e5f-6a7b8c9d0e1f',
  );
  const subject = '00000000-0000-0000-0000-000000000001';
  const deviceId = 'device-local-001';
  final signature = signer.sign(
    key: signingKey,
    subject: subject,
    deviceId: deviceId,
    amount: 25.3,
    recipientKey: 'recipient@example.com',
    description: 'Fixture pix',
    scenario: 'SUCCESS',
  );
  final plaintext = jsonEncode({
    'amount': 25.3,
    'recipientKey': 'recipient@example.com',
    'description': 'Fixture pix',
    'scenario': 'SUCCESS',
    'signature': signature,
  });
  const aad = 'POST /pix/transfers';
  final sealed = await envelope.seal(
    keySet: keySet,
    aad: aad,
    plaintext: Uint8List.fromList(utf8.encode(plaintext)),
    now: DateTime.utc(2026, 9, 19),
  );
  final headerOnly = await envelope.seal(keySet: keySet, aad: 'GET /statements', now: DateTime.utc(2026, 9, 19));

  // Raw shared secrets, recomputed on the backend side in Dart so the
  // OpenSSL checks can compare byte for byte.
  final mlkemSecret = PqcKem.kyber768.decapsulate(mlkemPrivateKey, sealed.message.mlkemCiphertext!);
  final x25519Secret = await x25519.sharedSecretKey(
    keyPair: x25519Pair,
    remotePublicKey: classical.SimplePublicKey(sealed.message.x25519PublicKey!, type: classical.KeyPairType.x25519),
  );

  final fixture = {
    'aad': aad,
    'keySet': keySet.toJson(),
    'backendPrivateKeys': {
      'mlkemPkcs8': base64.encode(PqcAsn1.mlKemPrivateKeyInfo(mlkemSeed)),
      'x25519Pkcs8': base64.encode(PqcAsn1.x25519PrivateKeyInfo(x25519Seed)),
    },
    'request': sealed.message.toJson(),
    'requestHeader': {'aad': 'GET /statements', 'value': headerOnly.message.toHeaderValue()},
    'plaintext': plaintext,
    'requestKey': base64.encode(sealed.session.requestKeyForTest),
    'sharedSecrets': {
      'mlkem': base64.encode(mlkemSecret),
      'x25519': base64.encode(await x25519Secret.extractBytes()),
    },
    'subject': subject,
    'deviceId': deviceId,
    'signingKeyRegistration': signingKey.registration(csrDer: csrDer),
    'csrDer': base64.encode(csrDer),
    'pixSignature': signature,
  };
  File('${outDir.path}/envelope-fixture.json').writeAsStringSync(
    const JsonEncoder.withIndent('  ').convert(fixture),
  );
  File('${outDir.path}/mlkem.key').writeAsStringSync(
    PqcAsn1.pem(PqcAsn1.pkcs8Label, PqcAsn1.mlKemPrivateKeyInfo(mlkemSeed)),
  );
  File('${outDir.path}/x25519.key').writeAsStringSync(
    PqcAsn1.pem(PqcAsn1.pkcs8Label, PqcAsn1.x25519PrivateKeyInfo(x25519Seed)),
  );
  File('${outDir.path}/x25519-eph.pub').writeAsStringSync(
    PqcAsn1.pem('PUBLIC KEY', PqcAsn1.x25519SubjectPublicKeyInfo(sealed.message.x25519PublicKey!)),
  );
  File('${outDir.path}/mlkem-ct.bin').writeAsBytesSync(sealed.message.mlkemCiphertext!);
  File('${outDir.path}/mlkem-ss.bin').writeAsBytesSync(mlkemSecret);
  File('${outDir.path}/x25519-ss.bin').writeAsBytesSync(await x25519Secret.extractBytes());
  stdout.writeln('emit-envelope-fixture-ok');
}
