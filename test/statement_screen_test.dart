import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/features/statements/statement_screen.dart';

void main() {
  testWidgets('renders statement entries from gateway API', (tester) async {
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: StatementScreen(api: DemoGatewayBankingApi()))));
    await tester.pumpAndSettle();

    expect(find.text('Extrato'), findsOneWidget);
    expect(find.text('Pix recebido - Cafeteria Horizonte'), findsOneWidget);
    expect(find.text('CREDIT'), findsOneWidget);
    expect(find.text('-42.90'), findsOneWidget);
  });
}
