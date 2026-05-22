import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/features/pix/pix_screen.dart';

void main() {
  testWidgets('submits Pix SUCCESS scenario', (tester) async {
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: PixScreen(api: DemoGatewayBankingApi()))));

    await tester.tap(find.text('Enviar Pix'));
    await tester.pumpAndSettle();

    expect(find.text('COMPLETED'), findsOneWidget);
  });

  testWidgets('submits Pix ERROR scenario and shows structured problem', (tester) async {
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: PixScreen(api: DemoGatewayBankingApi()))));

    await tester.tap(find.text('ERROR'));
    await tester.pump();
    await tester.tap(find.text('Enviar Pix'));
    await tester.pumpAndSettle();

    expect(find.text('pix_simulated_error'), findsOneWidget);
  });
}
