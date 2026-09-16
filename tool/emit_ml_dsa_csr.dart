// Emits an ML-DSA-65 CSR (and its PKCS#8 key) with the exact code path the app
// uses during enrollment, so other layers can verify interoperability:
//
//   dart run tool/emit_ml_dsa_csr.dart <out.csr> <out.key> [oauth2Subject]
//
// scripts/verify-pqc-csr-interop.sh feeds the output to OpenSSL >= 3.5 and the
// backend keeps a copy under src/test/resources/pqc as a fixture.
import 'dart:io';

import 'package:quantum_bank_mobile/features/bootstrap/csr_service.dart';
import 'package:quantum_bank_mobile/features/bootstrap/keypair_service.dart';

void main(List<String> args) {
  if (args.length < 2) {
    stderr.writeln('usage: emit_ml_dsa_csr.dart OUT_CSR OUT_KEY [oauth2Subject]');
    exit(2);
  }
  final subject = args.length > 2 ? args[2] : '00000000-0000-0000-0000-000000000001';
  final keys = KeypairService();
  final keyPair = keys.generateMlDsaKeyPair();
  final csrPem = CsrService().generatePem(
    input: CsrInput(
      oauth2Subject: subject,
      appInstanceId: 'app-local-001',
      deviceId: 'device-local-001',
      certificateProfile: 'quantum-bank-mobile-client-v1',
      environment: 'local',
    ),
    keyPair: keyPair,
  );
  File(args[0]).writeAsStringSync(csrPem);
  File(args[1]).writeAsStringSync(keys.encodePrivateKeyPem(keyPair));
  stdout.writeln('emit-ml-dsa-csr-ok ${keyPair.algorithm}');
}
