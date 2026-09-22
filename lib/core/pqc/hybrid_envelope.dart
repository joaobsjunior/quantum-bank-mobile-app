import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as classical;
import 'package:pointycastle/export.dart';
import 'package:pqcrypto/pqcrypto.dart';

/// Raised when an envelope, a key set or a response cannot be used.
class EnvelopeException implements Exception {
  const EnvelopeException(this.message);

  final String message;

  @override
  String toString() => 'EnvelopeException: $message';
}

/// The backend's public encapsulation keys for the application-layer
/// envelope (contract `envelope-v1`): an ML-KEM-768 encapsulation key (FIPS
/// 203) and an X25519 public key (RFC 7748). Both halves contribute to every
/// message secret, so the envelope keeps the security of whichever primitive
/// survives.
class EnvelopeKeySet {
  const EnvelopeKeySet({
    required this.kid,
    required this.mlkemPublicKey,
    required this.x25519PublicKey,
    required this.notAfter,
  });

  /// The only algorithm suite of envelope v1.
  static const String algorithm = 'X25519MLKEM768-HKDF-SHA256-AES256GCM';

  static const int mlkemPublicKeyLength = 1184;
  static const int x25519PublicKeyLength = 32;

  final String kid;
  final Uint8List mlkemPublicKey;
  final Uint8List x25519PublicKey;
  final DateTime notAfter;

  /// Parses the `keySet` object of the CSR response. Lengths and the
  /// algorithm suite are checked here so a malformed key set never reaches
  /// the KEM.
  factory EnvelopeKeySet.fromJson(Map<String, dynamic> json) {
    final alg = json['alg'];
    if (alg != algorithm) {
      throw EnvelopeException('unsupported envelope algorithm: $alg');
    }
    final kid = json['kid'];
    if (kid is! String || kid.isEmpty || kid.length > 64) {
      throw const EnvelopeException('invalid envelope key id');
    }
    final mlkem = _decodeBase64(json['mlkemPublicKey'], 'mlkemPublicKey');
    final x25519 = _decodeBase64(json['x25519PublicKey'], 'x25519PublicKey');
    if (mlkem.length != mlkemPublicKeyLength ||
        x25519.length != x25519PublicKeyLength) {
      throw const EnvelopeException('envelope public key has an invalid length');
    }
    final notAfter = json['notAfter'];
    if (notAfter is! String) {
      throw const EnvelopeException('envelope key set has no notAfter');
    }
    return EnvelopeKeySet(
      kid: kid,
      mlkemPublicKey: mlkem,
      x25519PublicKey: x25519,
      notAfter: DateTime.parse(notAfter).toUtc(),
    );
  }

  Map<String, Object?> toJson() => {
    'kid': kid,
    'alg': algorithm,
    'mlkemPublicKey': base64.encode(mlkemPublicKey),
    'x25519PublicKey': base64.encode(x25519PublicKey),
    'notAfter': _rfc3339(notAfter),
  };

  /// The bytes the backend signs (contract `envelope-v1`): one line per field,
  /// base64 values as transmitted, trailing newline.
  Uint8List canonicalBytes() => Uint8List.fromList(
    utf8.encode(
      '$kid\n$algorithm\n${base64.encode(mlkemPublicKey)}\n'
      '${base64.encode(x25519PublicKey)}\n${_rfc3339(notAfter)}\n',
    ),
  );

  bool isValidAt(DateTime now) => now.isBefore(notAfter);

  static String _rfc3339(DateTime time) =>
      time.toUtc().toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), 'Z');
}

/// One envelope on the wire (request or response). Request messages carry
/// the encapsulation (`mlkemCiphertext`, `x25519PublicKey`); response messages
/// only the AEAD output, because the response key derives from the request.
class EnvelopeMessage {
  const EnvelopeMessage({
    required this.kid,
    this.mlkemCiphertext,
    this.x25519PublicKey,
    this.nonce,
    this.ciphertext,
    this.contentType,
  });

  static const int version = 1;
  static const String mediaType = 'application/vnd.quantum-bank.envelope+json';
  static const String requestHeader = 'X-Quantum-Envelope';
  static const String contentTypeHeader = 'X-Quantum-Envelope-Content-Type';
  static const int mlkemCiphertextLength = 1088;
  static const int nonceLength = 12;

  final String kid;
  final Uint8List? mlkemCiphertext;
  final Uint8List? x25519PublicKey;
  final Uint8List? nonce;
  final Uint8List? ciphertext;
  final String? contentType;

  factory EnvelopeMessage.fromJson(Map<String, dynamic> json) {
    if (json['v'] != version) {
      throw EnvelopeException('unsupported envelope version: ${json['v']}');
    }
    final kid = json['kid'];
    if (kid is! String || kid.isEmpty) {
      throw const EnvelopeException('envelope without key id');
    }
    return EnvelopeMessage(
      kid: kid,
      mlkemCiphertext: _optionalBase64(json['mlkemCiphertext'], 'mlkemCiphertext'),
      x25519PublicKey: _optionalBase64(json['x25519PublicKey'], 'x25519PublicKey'),
      nonce: _optionalBase64(json['nonce'], 'nonce'),
      ciphertext: _optionalBase64(json['ciphertext'], 'ciphertext'),
      contentType: json['contentType'] as String?,
    );
  }

  /// Decodes the `X-Quantum-Envelope` header value (base64url, no padding).
  factory EnvelopeMessage.fromHeader(String value) => EnvelopeMessage.fromJson(
    jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(value))))
        as Map<String, dynamic>,
  );

  Map<String, Object?> toJson() => {
    'v': version,
    'kid': kid,
    if (mlkemCiphertext != null) 'mlkemCiphertext': base64.encode(mlkemCiphertext!),
    if (x25519PublicKey != null) 'x25519PublicKey': base64.encode(x25519PublicKey!),
    if (nonce != null) 'nonce': base64.encode(nonce!),
    if (ciphertext != null) 'ciphertext': base64.encode(ciphertext!),
    if (contentType != null) 'contentType': contentType,
  };

  /// Header form for requests without a body.
  String toHeaderValue() =>
      base64Url.encode(utf8.encode(jsonEncode(toJson()))).replaceAll('=', '');
}

/// The per-request secret state: the request key was used to seal the body,
/// the response key opens the backend's answer.
class EnvelopeSession {
  EnvelopeSession({
    required this.kid,
    required this.aad,
    required Uint8List requestKey,
    required Uint8List responseKey,
  }) : _requestKey = requestKey,
       _responseKey = responseKey;

  final String kid;
  final String aad;
  final Uint8List _requestKey;
  final Uint8List _responseKey;

  /// Opens a response envelope; any tag or key-id mismatch is an
  /// [EnvelopeException], never a partially decrypted body.
  Uint8List openResponse(EnvelopeMessage message) {
    if (message.kid != kid) {
      throw const EnvelopeException('response envelope key id mismatch');
    }
    final nonce = message.nonce;
    final ciphertext = message.ciphertext;
    if (nonce == null ||
        nonce.length != EnvelopeMessage.nonceLength ||
        ciphertext == null) {
      throw const EnvelopeException('response envelope is incomplete');
    }
    return HybridEnvelope.aesGcm(
      forEncryption: false,
      key: _responseKey,
      nonce: nonce,
      aad: utf8.encode(aad),
      input: ciphertext,
    );
  }

  /// Test seam: seals a plaintext the way the backend answers.
  Uint8List sealResponseForTest(Uint8List nonce, Uint8List plaintext) =>
      HybridEnvelope.aesGcm(
        forEncryption: true,
        key: _responseKey,
        nonce: nonce,
        aad: utf8.encode(aad),
        input: plaintext,
      );

  /// Test seam: the request key, to let a test server open the request.
  Uint8List get requestKeyForTest => Uint8List.fromList(_requestKey);
}

class SealedRequest {
  const SealedRequest({required this.message, required this.session});

  final EnvelopeMessage message;
  final EnvelopeSession session;
}

/// Hybrid application-layer envelope (contract `envelope-v1`):
///
/// ```text
/// ss     = ML-KEM-768.Encaps(ek) || X25519(sk_eph, pk_backend)
/// prk    = HKDF-Extract(SHA-256, salt = "quantum-bank-envelope-v1", ikm = ss)
/// k_req  = HKDF-Expand(prk, "request\0"  || kid || "\0" || aad, 32)
/// k_resp = HKDF-Expand(prk, "response\0" || kid || "\0" || aad, 32)
/// body   = AES-256-GCM(k, nonce, plaintext, aad)   aad = METHOD + " " + PATH
/// ```
///
/// The construction mirrors the `X25519MLKEM768` TLS key exchange (secrets
/// concatenated, post-quantum half first) so the transport and the
/// application layer rest on the same argument, and it works on any TLS
/// stack because it never touches the socket.
class HybridEnvelope {
  HybridEnvelope({Random? random, classical.X25519? x25519})
    : _random = random ?? Random.secure(),
      _x25519 = x25519 ?? classical.X25519();

  static final Uint8List salt = Uint8List.fromList(
    utf8.encode('quantum-bank-envelope-v1'),
  );
  static const int keyLength = 32;
  static const int tagBits = 128;

  final Random _random;
  final classical.X25519 _x25519;
  final KyberKem _kem = PqcKem.kyber768;

  /// Encapsulates to [keySet], derives the request and response keys for
  /// [aad] and seals [plaintext] (absent for requests without a body).
  Future<SealedRequest> seal({
    required EnvelopeKeySet keySet,
    required String aad,
    Uint8List? plaintext,
    DateTime? now,
  }) async {
    if (!keySet.isValidAt(now ?? DateTime.now().toUtc())) {
      throw const EnvelopeException('envelope key set expired');
    }
    final (mlkemCiphertext, mlkemSecret) = _kem.encapsulate(keySet.mlkemPublicKey);
    final ephemeral = await _x25519.newKeyPairFromSeed(randomBytes(32));
    final x25519Secret = await _x25519.sharedSecretKey(
      keyPair: ephemeral,
      remotePublicKey: classical.SimplePublicKey(
        keySet.x25519PublicKey,
        type: classical.KeyPairType.x25519,
      ),
    );
    final ephemeralPublic = await ephemeral.extractPublicKey();
    final (requestKey, responseKey) = deriveKeys(
      mlkemSecret: mlkemSecret,
      x25519Secret: Uint8List.fromList(await x25519Secret.extractBytes()),
      kid: keySet.kid,
      aad: aad,
    );
    final session = EnvelopeSession(
      kid: keySet.kid,
      aad: aad,
      requestKey: requestKey,
      responseKey: responseKey,
    );
    Uint8List? nonce;
    Uint8List? ciphertext;
    if (plaintext != null) {
      nonce = randomBytes(EnvelopeMessage.nonceLength);
      ciphertext = aesGcm(
        forEncryption: true,
        key: requestKey,
        nonce: nonce,
        aad: utf8.encode(aad),
        input: plaintext,
      );
    }
    return SealedRequest(
      message: EnvelopeMessage(
        kid: keySet.kid,
        mlkemCiphertext: mlkemCiphertext,
        x25519PublicKey: Uint8List.fromList(ephemeralPublic.bytes),
        nonce: nonce,
        ciphertext: ciphertext,
      ),
      session: session,
    );
  }

  /// HKDF-SHA-256 key schedule shared with the backend and the test server.
  static (Uint8List, Uint8List) deriveKeys({
    required Uint8List mlkemSecret,
    required Uint8List x25519Secret,
    required String kid,
    required String aad,
  }) {
    final ikm = Uint8List.fromList([...mlkemSecret, ...x25519Secret]);
    Uint8List expand(String direction) {
      final info = Uint8List.fromList([
        ...utf8.encode(direction),
        0,
        ...utf8.encode(kid),
        0,
        ...utf8.encode(aad),
      ]);
      final derivator = HKDFKeyDerivator(SHA256Digest())
        ..init(HkdfParameters(ikm, keyLength, salt, info));
      final out = Uint8List(keyLength);
      derivator.deriveKey(null, 0, out, 0);
      return out;
    }

    return (expand('request'), expand('response'));
  }

  /// AES-256-GCM with a 128-bit tag; decryption failures surface as
  /// [EnvelopeException].
  static Uint8List aesGcm({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List nonce,
    required List<int> aad,
    required Uint8List input,
  }) {
    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        forEncryption,
        AEADParameters(
          KeyParameter(key),
          tagBits,
          nonce,
          Uint8List.fromList(aad),
        ),
      );
    try {
      return cipher.process(input);
    } on InvalidCipherTextException {
      throw const EnvelopeException('envelope authentication failed');
    }
  }

  Uint8List randomBytes(int length) => Uint8List.fromList(
    List<int>.generate(length, (_) => _random.nextInt(256), growable: false),
  );
}

Uint8List _decodeBase64(Object? value, String field) {
  if (value is! String) {
    throw EnvelopeException('missing envelope field $field');
  }
  try {
    return base64.decode(value);
  } on FormatException {
    throw EnvelopeException('invalid base64 in envelope field $field');
  }
}

Uint8List? _optionalBase64(Object? value, String field) =>
    value == null ? null : _decodeBase64(value, field);
