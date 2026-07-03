import 'package:test/test.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

void main() {
  test('generates an RSA keypair and encodes the private key as PEM', () {
    final service = KeypairService();

    final pair = service.generateRsaKeyPair(bitLength: 1024);
    final pem = service.encodePrivateKeyPem(pair.privateKey);

    expect(pem, contains('PRIVATE KEY'));
    expect(pair.publicKey.modulus, isNotNull);
  });
}
