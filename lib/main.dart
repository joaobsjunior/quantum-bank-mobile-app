import 'package:flutter/material.dart';

import 'app/app_state.dart';
import 'core/api/gateway_api.dart';
import 'features/pix/pix_screen.dart';
import 'features/profile/profile_screen.dart';
import 'features/statements/statement_screen.dart';

void main() {
  runApp(QuantumBankApp(api: DemoGatewayBankingApi()));
}

class QuantumBankApp extends StatefulWidget {
  const QuantumBankApp({
    required this.api,
    QuantumBankAppState? appState,
    super.key,
  }) : appState = appState ?? null;

  final GatewayBankingApi api;
  final QuantumBankAppState? appState;

  @override
  State<QuantumBankApp> createState() => _QuantumBankAppState();
}

class _QuantumBankAppState extends State<QuantumBankApp> {
  late final QuantumBankAppState appState = widget.appState ?? QuantumBankAppState();

  @override
  void initState() {
    super.initState();
    appState.addListener(_refresh);
  }

  @override
  void dispose() {
    appState.removeListener(_refresh);
    super.dispose();
  }

  void _refresh() => setState(() {});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Quantum Bank',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF176B5B)),
        useMaterial3: true,
      ),
      home: QuantumBankHome(appState: appState, api: widget.api),
    );
  }
}

class QuantumBankHome extends StatefulWidget {
  const QuantumBankHome({
    required this.appState,
    required this.api,
    super.key,
  });

  final QuantumBankAppState appState;
  final GatewayBankingApi api;

  @override
  State<QuantumBankHome> createState() => _QuantumBankHomeState();
}

class _QuantumBankHomeState extends State<QuantumBankHome> {
  int selectedIndex = 0;

  @override
  Widget build(BuildContext context) {
    if (!widget.appState.protectedReady) {
      return Scaffold(
        appBar: AppBar(title: const Text('Quantum Bank')),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.lock_outline, size: 40),
                  const SizedBox(height: 16),
                  Text(
                    'Acesso protegido',
                    style: Theme.of(context).textTheme.headlineSmall,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    widget.appState.authenticated
                        ? 'Certificado do dispositivo pendente.'
                        : 'Autenticação OAuth2 pendente.',
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: widget.appState.authenticate,
                    icon: const Icon(Icons.verified_user_outlined),
                    label: const Text('Autenticar'),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: widget.appState.authenticated ? widget.appState.markCertificateReady : null,
                    icon: const Icon(Icons.badge_outlined),
                    label: const Text('Ativar certificado'),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }

    final pages = <Widget>[
      PixScreen(api: widget.api),
      StatementScreen(api: widget.api),
      ProfileScreen(api: widget.api),
    ];

    return Scaffold(
      appBar: AppBar(title: const Text('Quantum Bank')),
      body: pages[selectedIndex],
      bottomNavigationBar: NavigationBar(
        selectedIndex: selectedIndex,
        onDestinationSelected: (index) => setState(() => selectedIndex = index),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.payments_outlined), label: 'Pix'),
          NavigationDestination(icon: Icon(Icons.receipt_long_outlined), label: 'Extrato'),
          NavigationDestination(icon: Icon(Icons.person_outline), label: 'Perfil'),
        ],
      ),
    );
  }
}
