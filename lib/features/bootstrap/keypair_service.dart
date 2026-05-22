import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

class KeypairService {
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKeyPair({
    int bitLength = 2048,
  }) {
    final generator = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.from(65537), bitLength, 64),
          _secureRandom(),
        ),
      );

    final keyPair = generator.generateKeyPair();
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      keyPair.publicKey as RSAPublicKey,
      keyPair.privateKey as RSAPrivateKey,
    );
  }

  SecureRandom _secureRandom() {
    final seed = Uint8List(32);
    final random = Random.secure();
    for (var index = 0; index < seed.length; index += 1) {
      seed[index] = random.nextInt(256);
    }

    return FortunaRandom()..seed(KeyParameter(seed));
  }
}
