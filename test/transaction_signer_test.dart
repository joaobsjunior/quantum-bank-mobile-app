import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/pqc_asn1.dart';
import 'package:quantum_bank_mobile/core/pqc/transaction_signer.dart';

void main() {
  final key = DeviceSigningKey.fromSeed(Uint8List.fromList(List<int>.filled(32, 7)));

  test('generates an ML-DSA-65 signing key that re-derives from its seed', () {
    final generated = DeviceSigningKey.generate(random: Random(1));
    expect(generated.publicKey, hasLength(1952));
    expect(generated.algorithm, equals('ML-DSA-65'));
    expect(DeviceSigningKey.fromSeed(generated.seed).publicKey, equals(generated.publicKey));
    expect(DeviceSigningKey.generate().publicKey, isNot(equals(generated.publicKey)));
    expect(generated.privateKeyPem(), startsWith('-----BEGIN PRIVATE KEY-----'));
    expect(
      PqcAsn1.derFromPem(generated.privateKeyPem(), PqcAsn1.pkcs8Label),
      containsAllInOrder([0x80, 0x20, ...generated.seed]),
    );
  });

  test('registration carries the public key and a proof over the CSR', () {
    final csrDer = Uint8List.fromList(utf8.encode('csr-der'));
    final registration = key.registration(csrDer: csrDer);

    expect(registration['alg'], equals('ML-DSA-65'));
    expect(base64.decode(registration['publicKey'] as String), equals(key.publicKey));
    final proof = base64.decode(registration['proof'] as String);
    expect(key.verify(csrDer, proof, context: DeviceSigningKey.registrationContext), isTrue);
    expect(key.verify(csrDer, proof, context: PixTransactionSigner.context), isFalse);
    expect(key.verify(Uint8List.fromList(utf8.encode('other')), proof, context: DeviceSigningKey.registrationContext), isFalse);
  });

  test('signs Pix orders over the canonical message with the pix context', () {
    final signer = PixTransactionSigner(
      clock: () => DateTime.utc(2026, 9, 19, 12, 0, 0),
      nonceGenerator: () => '11111111-2222-4333-8444-555555555555',
    );

    final signature = signer.sign(
      key: key,
      subject: 'alice@quantumbank.local',
      deviceId: 'device-local-001',
      amount: 25.3,
      recipientKey: 'recipient@example.com',
      description: 'Transferencia local',
      scenario: 'SUCCESS',
    );

    expect(signature['alg'], equals('ML-DSA-65'));
    expect(signature['deviceId'], equals('device-local-001'));
    expect(signature['nonce'], equals('11111111-2222-4333-8444-555555555555'));
    expect(signature['issuedAt'], equals('2026-09-19T12:00:00.000Z'));
    final message = PixTransactionSigner.canonicalMessage(
      subject: 'alice@quantumbank.local',
      deviceId: 'device-local-001',
      amount: 25.3,
      recipientKey: 'recipient@example.com',
      description: 'Transferencia local',
      scenario: 'SUCCESS',
      nonce: '11111111-2222-4333-8444-555555555555',
      issuedAt: '2026-09-19T12:00:00.000Z',
    );
    expect(
      utf8.decode(message),
      equals(
        'quantum-bank-pix-v1\nalice@quantumbank.local\ndevice-local-001\n25.30\n'
        'recipient@example.com\nTransferencia local\nSUCCESS\n'
        '11111111-2222-4333-8444-555555555555\n2026-09-19T12:00:00.000Z\n',
      ),
    );
    expect(key.verify(message, base64.decode(signature['value'] as String), context: PixTransactionSigner.context), isTrue);
  });

  test('default signer uses the clock and a random UUID v4 nonce', () {
    final signature = PixTransactionSigner().sign(
      key: key,
      subject: 's',
      deviceId: 'd',
      amount: 1,
      recipientKey: 'r',
      description: '',
      scenario: 'ERROR',
    );

    expect(signature['nonce'] as String, matches(RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')));
    expect(DateTime.parse(signature['issuedAt'] as String).isUtc, isTrue);
    expect(PixTransactionSigner.randomUuid(random: Random(3)), isNot(equals(PixTransactionSigner.randomUuid(random: Random(4)))));
  });
}
