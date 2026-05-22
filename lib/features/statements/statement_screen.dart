import 'package:flutter/material.dart';

import '../../core/api/gateway_api.dart';

class StatementScreen extends StatelessWidget {
  const StatementScreen({required this.api, super.key});

  final GatewayBankingApi api;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<StatementItem>>(
      future: api.loadStatements(),
      builder: (context, snapshot) {
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('Extrato', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 16),
            if (!snapshot.hasData)
              const LinearProgressIndicator()
            else
              for (final entry in snapshot.data!)
                ListTile(
                  leading: Icon(
                    entry.amount >= 0 ? Icons.south_west : Icons.north_east,
                  ),
                  title: Text(entry.description),
                  subtitle: Text(entry.type),
                  trailing: Text(entry.amount.toStringAsFixed(2)),
                ),
          ],
        );
      },
    );
  }
}
