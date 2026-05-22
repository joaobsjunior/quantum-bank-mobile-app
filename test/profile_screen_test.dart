import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';
import 'package:quantum_bank_mobile/features/profile/profile_screen.dart';

void main() {
  testWidgets('loads and edits customer registration profile', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: ProfileScreen(api: DemoGatewayBankingApi())),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Customer registration data'), findsOneWidget);
    expect(find.text('Alice Quantum'), findsOneWidget);

    await tester.enterText(find.byType(TextField).first, 'Alice Quantum UI');
    await tester.tap(find.text('Salvar perfil'));
    await tester.pumpAndSettle();

    expect(find.text('Perfil atualizado'), findsOneWidget);
    expect(find.text('PUT /profile via profile:write'), findsOneWidget);
  });
}
