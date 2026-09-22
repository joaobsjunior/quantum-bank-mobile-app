import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/pqc/hybrid_envelope.dart';

import 'support/envelope_test_server.dart';

void main() {
  late EnvelopeTestServer server;

  setUpAll(() async {
    server = await EnvelopeTestServer.create();
  });

  Map<String, dynamic> keySetJson() => Map<String, dynamic>.from(server.keySet.toJson());

  test('key set JSON round-trips and produces canonical bytes with RFC 3339 time', () {
    final parsed = EnvelopeKeySet.fromJson(keySetJson());

    expect(parsed.kid, equals('test-kid-001'));
    expect(parsed.mlkemPublicKey, equals(server.keySet.mlkemPublicKey));
    expect(parsed.x25519PublicKey, equals(server.keySet.x25519PublicKey));
    expect(parsed.notAfter, equals(DateTime.utc(2027, 1, 1)));
    expect(parsed.isValidAt(DateTime.utc(2026, 12, 31)), isTrue);
    expect(parsed.isValidAt(DateTime.utc(2027, 1, 1)), isFalse);
    final canonical = utf8.decode(parsed.canonicalBytes());
    expect(canonical, startsWith('test-kid-001\n${EnvelopeKeySet.algorithm}\n'));
    expect(canonical, endsWith('\n2027-01-01T00:00:00Z\n'));
    expect(
      EnvelopeKeySet.fromJson({...keySetJson(), 'notAfter': '2027-01-01T00:00:00.123456Z'})
          .canonicalBytes(),
      equals(parsed.canonicalBytes()),
    );
  });

  test('key set JSON validation fails closed', () {
    void expectFails(Map<String, dynamic> json, String fragment) {
      expect(
        () => EnvelopeKeySet.fromJson(json),
        throwsA(isA<EnvelopeException>().having((e) => e.toString(), 'message', contains(fragment))),
      );
    }

    expectFails({...keySetJson(), 'alg': 'RSA-OAEP'}, 'unsupported envelope algorithm');
    expectFails({...keySetJson(), 'kid': ''}, 'invalid envelope key id');
    expectFails({...keySetJson(), 'kid': 'k' * 65}, 'invalid envelope key id');
    expectFails({...keySetJson()}..remove('mlkemPublicKey'), 'missing envelope field mlkemPublicKey');
    expectFails({...keySetJson(), 'x25519PublicKey': '***'}, 'invalid base64');
    expectFails({...keySetJson(), 'x25519PublicKey': base64.encode(Uint8List(31))}, 'invalid length');
    expectFails({...keySetJson(), 'mlkemPublicKey': base64.encode(Uint8List(1183))}, 'invalid length');
    expectFails({...keySetJson()}..remove('notAfter'), 'no notAfter');
  });

  test('seals a request the server can open and opens the server response', () async {
    final envelope = HybridEnvelope();
    const aad = 'POST /pix/transfers';
    final sealed = await envelope.seal(
      keySet: server.keySet,
      aad: aad,
      plaintext: Uint8List.fromList(utf8.encode('{"amount":25.30}')),
      now: DateTime.utc(2026, 10, 1),
    );

    expect(sealed.message.kid, equals('test-kid-001'));
    expect(sealed.message.mlkemCiphertext, hasLength(EnvelopeMessage.mlkemCiphertextLength));
    expect(sealed.message.x25519PublicKey, hasLength(32));
    expect(sealed.message.nonce, hasLength(EnvelopeMessage.nonceLength));
    expect(sealed.message.ciphertext, hasLength('{"amount":25.30}'.length + 16));

    final wire = EnvelopeMessage.fromJson(
      jsonDecode(jsonEncode(sealed.message.toJson())) as Map<String, dynamic>,
    );
    final (plaintext, responseKey) = await server.open(wire, aad);
    expect(utf8.decode(plaintext), equals('{"amount":25.30}'));

    final response = server.sealResponse(
      responseKey: responseKey,
      kid: 'test-kid-001',
      aad: aad,
      body: '{"status":"COMPLETED"}',
    );
    final opened = sealed.session.openResponse(
      EnvelopeMessage.fromJson(jsonDecode(jsonEncode(response.toJson())) as Map<String, dynamic>),
    );
    expect(utf8.decode(opened), equals('{"status":"COMPLETED"}'));
    expect(response.toJson()['contentType'], equals('application/json'));
  });

  test('a request without a body travels as a header the server can open', () async {
    const aad = 'GET /statements';
    final sealed = await HybridEnvelope().seal(keySet: server.keySet, aad: aad);

    expect(sealed.message.nonce, isNull);
    expect(sealed.message.ciphertext, isNull);
    final header = sealed.message.toHeaderValue();
    expect(header, isNot(contains('=')));

    final (plaintext, responseKey) = await server.open(EnvelopeMessage.fromHeader(header), aad);
    expect(plaintext, isEmpty);
    expect(responseKey, hasLength(32));
    expect(sealed.session.requestKeyForTest, hasLength(32));
    expect(sealed.session.requestKeyForTest, isNot(equals(responseKey)));
  });

  test('every seal uses fresh randomness', () async {
    final envelope = HybridEnvelope();
    final first = await envelope.seal(keySet: server.keySet, aad: 'GET /profile');
    final second = await envelope.seal(keySet: server.keySet, aad: 'GET /profile');

    expect(first.message.mlkemCiphertext, isNot(equals(second.message.mlkemCiphertext)));
    expect(first.message.x25519PublicKey, isNot(equals(second.message.x25519PublicKey)));
  });

  test('refuses to encrypt to an expired key set', () async {
    await expectLater(
      HybridEnvelope().seal(keySet: server.keySet, aad: 'GET /profile', now: DateTime.utc(2027, 6, 1)),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('expired'))),
    );
  });

  test('response envelopes with the wrong key id, incomplete fields or a bad tag are rejected', () async {
    const aad = 'GET /profile';
    final sealed = await HybridEnvelope().seal(keySet: server.keySet, aad: aad);
    final nonce = Uint8List(12);
    final ciphertext = sealed.session.sealResponseForTest(nonce, Uint8List.fromList(utf8.encode('{}')));

    expect(
      () => sealed.session.openResponse(EnvelopeMessage(kid: 'other', nonce: nonce, ciphertext: ciphertext)),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('key id mismatch'))),
    );
    expect(
      () => sealed.session.openResponse(const EnvelopeMessage(kid: 'test-kid-001')),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('incomplete'))),
    );
    expect(
      () => sealed.session.openResponse(EnvelopeMessage(kid: 'test-kid-001', nonce: Uint8List(11), ciphertext: ciphertext)),
      throwsA(isA<EnvelopeException>()),
    );
    final tampered = Uint8List.fromList(ciphertext)..[0] ^= 0x01;
    expect(
      () => sealed.session.openResponse(EnvelopeMessage(kid: 'test-kid-001', nonce: nonce, ciphertext: tampered)),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('authentication failed'))),
    );
    expect(
      utf8.decode(sealed.session.openResponse(EnvelopeMessage(kid: 'test-kid-001', nonce: nonce, ciphertext: ciphertext))),
      equals('{}'),
    );
  });

  test('message JSON validation fails closed', () {
    expect(
      () => EnvelopeMessage.fromJson({'v': 2, 'kid': 'k'}),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('unsupported envelope version'))),
    );
    expect(
      () => EnvelopeMessage.fromJson({'v': 1}),
      throwsA(isA<EnvelopeException>().having((e) => e.message, 'message', contains('without key id'))),
    );
    expect(
      () => EnvelopeMessage.fromJson({'v': 1, 'kid': 'k', 'nonce': '!!'}),
      throwsA(isA<EnvelopeException>()),
    );
    expect(const EnvelopeException('x').toString(), equals('EnvelopeException: x'));
  });

  test('key schedule is deterministic and direction-separated', () {
    final mlkem = Uint8List.fromList(List<int>.filled(32, 1));
    final x = Uint8List.fromList(List<int>.filled(32, 2));
    final (req1, resp1) = HybridEnvelope.deriveKeys(mlkemSecret: mlkem, x25519Secret: x, kid: 'k', aad: 'GET /a');
    final (req2, resp2) = HybridEnvelope.deriveKeys(mlkemSecret: mlkem, x25519Secret: x, kid: 'k', aad: 'GET /a');
    final (req3, _) = HybridEnvelope.deriveKeys(mlkemSecret: mlkem, x25519Secret: x, kid: 'k', aad: 'GET /b');

    expect(req1, equals(req2));
    expect(resp1, equals(resp2));
    expect(req1, isNot(equals(resp1)));
    expect(req1, isNot(equals(req3)));
  });
}
