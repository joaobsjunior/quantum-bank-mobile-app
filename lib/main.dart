import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app/app_state.dart';
import 'core/api/banking_client.dart';
import 'core/api/gateway_api.dart';
import 'core/api/live_gateway_banking_api.dart';
import 'core/config/runtime_config.dart';
import 'core/pqc/envelope_keys_verifier.dart';
import 'core/tls/pqc_tls_support.dart';
import 'features/auth/keycloak_auth_client.dart';
import 'features/bootstrap/bootstrap_client.dart';
import 'features/bootstrap/enrollment_orchestrator.dart';
import 'features/pix/pix_screen.dart';
import 'features/profile/profile_screen.dart';
import 'features/statements/statement_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final config = RuntimeConfig.fromEnvironment();
  final postQuantumRoot = (await rootBundle.load(
    config.trustedCaAsset,
  )).buffer.asUint8List().toList(growable: false);
  final compatibilityRoot = (await rootBundle.load(
    config.compatTrustedCaAsset,
  )).buffer.asUint8List().toList(growable: false);
  // Decide the transport mode before any socket is opened. The default policy
  // is the compatibility transport (ECDSA P-256 identity), because no current
  // Dart release can present an ML-DSA identity in the TLS handshake; the
  // post-quantum protection of the app edge is the application envelope and
  // the ML-DSA-65 transaction signatures, which do not depend on the TLS
  // stack. `PQC_TRANSPORT_POLICY=probe` restores the feature 011 probe.
  final pqcTransport = switch (config.transportPolicy) {
    TransportPolicy.probe => const PqcTlsSupport().probe(
      mlDsaCertificateBytes: postQuantumRoot,
    ),
    TransportPolicy.compatibility =>
      const PqcTransportStatus.compatibilityByPolicy(),
  };
  final trustedCaBytes = trustAnchorsFor(
    pqcTransport.mode,
    postQuantumRoot: postQuantumRoot,
    compatibilityRoot: compatibilityRoot,
  );
  final appState = QuantumBankAppState(
    pqcTransport: pqcTransport,
    authenticator: KeycloakAuthClient(
      tokenUrl: config.keycloakTokenUrl,
      clientId: config.keycloakClientId,
      clientSecret: config.keycloakClientSecret,
      username: config.localUsername,
      password: config.localPassword,
      trustedCaBytes: trustedCaBytes,
    ),
    certificateEnrollment: EnrollmentOrchestrator(
      bootstrapGateway: BootstrapClient(
        baseUrl: config.gatewayBootstrapBaseUrl,
        trustedCaBytes: trustedCaBytes,
      ),
      transportMode: pqcTransport.mode,
      // The envelope key set is verified in Dart against the ML-DSA-87 root
      // in every transport mode; the compatibility TLS chain never decides it.
      envelopeKeysVerifier: EnvelopeKeysVerifier(
        trustAnchorPem: postQuantumRoot,
        expectedSignerCommonName: config.envelopeSignerCommonName,
      ),
    ),
    runtimeConfig: config,
  );
  final api = LiveGatewayBankingApi(
    bankingClient: BankingClient(
      gatewayBaseUrl: config.gatewayBaseUrl,
      trustedCaBytes: trustedCaBytes,
    ),
    // Provider closures are exercised by the live gateway path (e2e job),
    // not by unit tests, which never drive a real banking call through main().
    authSessionProvider: () => appState.authSession, // coverage:ignore-line
    certStateProvider: () => appState.certificateState, // coverage:ignore-line
  );

  runApp(QuantumBankApp(api: api, appState: appState));
}

class QuantumBankApp extends StatefulWidget {
  const QuantumBankApp({required this.api, required this.appState, super.key});

  final GatewayBankingApi api;
  final QuantumBankAppState appState;

  @override
  State<QuantumBankApp> createState() => _QuantumBankAppState();
}

class _QuantumBankAppState extends State<QuantumBankApp> {
  late final QuantumBankAppState appState = widget.appState;

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
  const QuantumBankHome({required this.appState, required this.api, super.key});

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
          child: SingleChildScrollView(
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
                  const SizedBox(height: 8),
                  Text(
                    widget.appState.transportLabel,
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    widget.appState.envelopeLabel,
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  if (!widget.appState.pqcTransportSupported) ...[
                    const SizedBox(height: 4),
                    Text(
                      widget.appState.pqcTransport.reason ?? '',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: widget.appState.authenticating
                        ? null
                        : () => widget.appState.authenticate(),
                    icon: const Icon(Icons.verified_user_outlined),
                    label: Text(
                      widget.appState.authenticating
                          ? 'Autenticando...'
                          : 'Autenticar',
                    ),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed:
                        widget.appState.authenticated &&
                            !widget.appState.enrollingCertificate
                        ? () => widget.appState.markCertificateReady()
                        : null,
                    icon: const Icon(Icons.badge_outlined),
                    label: Text(
                      widget.appState.enrollingCertificate
                          ? 'Ativando...'
                          : 'Ativar certificado',
                    ),
                  ),
                  if (widget.appState.lastError != null) ...[
                    const SizedBox(height: 12),
                    Text(
                      widget.appState.lastError!,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ],
                ],
              ),
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
          NavigationDestination(
            icon: Icon(Icons.payments_outlined),
            label: 'Pix',
          ),
          NavigationDestination(
            icon: Icon(Icons.receipt_long_outlined),
            label: 'Extrato',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_outline),
            label: 'Perfil',
          ),
        ],
      ),
    );
  }
}
