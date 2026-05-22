import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/main.dart';

void main() {
  testWidgets('blocks protected screens until authenticated and certificateReady', (tester) async {
    await tester.pumpWidget(QuantumBankApp(api: DemoGatewayBankingApi()));

    expect(find.text('Acesso protegido'), findsOneWidget);
    expect(find.text('Pix'), findsNothing);

    await tester.tap(find.text('Autenticar'));
    await tester.pump();

    expect(find.text('Certificado do dispositivo pendente.'), findsOneWidget);
    expect(find.text('Pix'), findsNothing);

    await tester.tap(find.text('Ativar certificado'));
    await tester.pumpAndSettle();

    expect(find.text('Pix'), findsWidgets);
    expect(find.text('Extrato'), findsOneWidget);
    expect(find.text('Perfil'), findsOneWidget);
  });
}
