import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'production entrypoint wires live KrakenD clients instead of the demo API',
    () async {
      final mainSource = await File('lib/main.dart').readAsString();

      expect(mainSource, contains('LiveGatewayBankingApi'));
      expect(mainSource, isNot(contains('DemoGatewayBankingApi()')));
      expect(mainSource, contains('KeycloakAuthClient'));
      expect(mainSource, contains('BootstrapClient'));
      expect(mainSource, contains('PqcTlsSupport'));
      expect(mainSource, contains('pqcTransport: pqcTransport'));
      expect(mainSource, contains('transportMode: pqcTransport.mode'));
      expect(mainSource, contains('trustAnchorsFor('));
      expect(mainSource, contains('config.compatTrustedCaAsset'));
    },
  );
}
