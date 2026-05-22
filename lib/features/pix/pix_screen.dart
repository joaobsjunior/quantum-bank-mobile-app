import 'package:flutter/material.dart';

import '../../core/api/gateway_api.dart';

class PixScreen extends StatefulWidget {
  const PixScreen({required this.api, super.key});

  final GatewayBankingApi api;

  @override
  State<PixScreen> createState() => _PixScreenState();
}

class _PixScreenState extends State<PixScreen> {
  final amountController = TextEditingController(text: '25.30');
  final recipientController = TextEditingController(
    text: 'recipient@example.com',
  );
  final descriptionController = TextEditingController(
    text: 'Transferencia local',
  );
  PixScenario scenario = PixScenario.success;
  PixResult? result;
  GatewayProblem? problem;
  bool loading = false;

  @override
  void dispose() {
    amountController.dispose();
    recipientController.dispose();
    descriptionController.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    setState(() {
      loading = true;
      result = null;
      problem = null;
    });

    try {
      final response = await widget.api.submitPix(
        amount: double.parse(amountController.text),
        recipientKey: recipientController.text,
        description: descriptionController.text,
        scenario: scenario,
      );
      setState(() => result = response);
    } on GatewayProblemException catch (exception) {
      setState(() => problem = exception.problem);
    } finally {
      if (mounted) {
        setState(() => loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text('Pix', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 16),
        TextField(
          controller: amountController,
          decoration: const InputDecoration(
            labelText: 'Valor',
            prefixIcon: Icon(Icons.attach_money),
          ),
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: recipientController,
          decoration: const InputDecoration(
            labelText: 'Chave Pix',
            prefixIcon: Icon(Icons.alternate_email),
          ),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: descriptionController,
          decoration: const InputDecoration(
            labelText: 'Descricao',
            prefixIcon: Icon(Icons.notes_outlined),
          ),
        ),
        const SizedBox(height: 16),
        SegmentedButton<PixScenario>(
          segments: const [
            ButtonSegment(
              value: PixScenario.success,
              label: Text('SUCCESS'),
              icon: Icon(Icons.check_circle_outline),
            ),
            ButtonSegment(
              value: PixScenario.error,
              label: Text('ERROR'),
              icon: Icon(Icons.error_outline),
            ),
          ],
          selected: {scenario},
          onSelectionChanged: (value) =>
              setState(() => scenario = value.single),
        ),
        const SizedBox(height: 16),
        FilledButton.icon(
          onPressed: loading ? null : submit,
          icon: const Icon(Icons.send_outlined),
          label: Text(loading ? 'Enviando' : 'Enviar Pix'),
        ),
        const SizedBox(height: 24),
        if (result != null)
          ListTile(
            leading: const Icon(Icons.verified_outlined),
            title: Text(result!.status),
            subtitle: Text(
              '${result!.transactionId} - ${result!.correlationId}',
            ),
          ),
        if (problem != null)
          ListTile(
            leading: const Icon(Icons.report_gmailerrorred_outlined),
            title: Text(problem!.errorCode),
            subtitle: Text(problem!.detail),
          ),
      ],
    );
  }
}
