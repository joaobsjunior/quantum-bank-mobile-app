import 'dart:math';

import 'package:flutter/foundation.dart';

enum PixScenario { success, error }

@immutable
class PixResult {
  const PixResult({
    required this.transactionId,
    required this.status,
    required this.amount,
    required this.correlationId,
  });

  final String transactionId;
  final String status;
  final double amount;
  final String correlationId;
}

@immutable
class GatewayProblem {
  const GatewayProblem({
    required this.errorCode,
    required this.title,
    required this.detail,
    required this.correlationId,
  });

  final String errorCode;
  final String title;
  final String detail;
  final String correlationId;
}

class GatewayProblemException implements Exception {
  const GatewayProblemException(this.problem);

  final GatewayProblem problem;
}

@immutable
class StatementItem {
  const StatementItem({
    required this.description,
    required this.amount,
    required this.type,
    required this.postedAt,
  });

  final String description;
  final double amount;
  final String type;
  final DateTime postedAt;
}

@immutable
class CustomerProfile {
  const CustomerProfile({
    required this.fullName,
    required this.email,
    required this.phone,
    required this.documentNumber,
    required this.address,
  });

  final String fullName;
  final String email;
  final String phone;
  final String documentNumber;
  final String address;

  CustomerProfile copyWith({
    String? fullName,
    String? email,
    String? phone,
    String? address,
  }) => CustomerProfile(
    fullName: fullName ?? this.fullName,
    email: email ?? this.email,
    phone: phone ?? this.phone,
    documentNumber: documentNumber,
    address: address ?? this.address,
  );
}

abstract interface class GatewayBankingApi {
  Future<PixResult> submitPix({
    required double amount,
    required String recipientKey,
    required String description,
    required PixScenario scenario,
  });

  Future<List<StatementItem>> loadStatements();

  Future<CustomerProfile> loadProfile();

  Future<CustomerProfile> updateProfile(CustomerProfile profile);
}

class DemoGatewayBankingApi implements GatewayBankingApi {
  CustomerProfile _profile = const CustomerProfile(
    fullName: 'Alice Quantum',
    email: 'alice@quantumbank.local',
    phone: '+55 71 90000-0001',
    documentNumber: '123.456.789-00',
    address: 'Av. Oceano Seguro, 100 - Salvador, BA',
  );

  @override
  Future<PixResult> submitPix({
    required double amount,
    required String recipientKey,
    required String description,
    required PixScenario scenario,
  }) async {
    if (scenario == PixScenario.error) {
      throw GatewayProblemException(
        GatewayProblem(
          errorCode: 'pix_simulated_error',
          title: 'Pix simulation failed',
          detail:
              'Pix transfer was rejected by the selected local simulation scenario.',
          correlationId: _correlationId(),
        ),
      );
    }

    return PixResult(
      transactionId: 'pix-${Random().nextInt(900000) + 100000}',
      status: 'COMPLETED',
      amount: amount,
      correlationId: _correlationId(),
    );
  }

  @override
  Future<List<StatementItem>> loadStatements() async => [
    StatementItem(
      description: 'Pix recebido - Cafeteria Horizonte',
      amount: 125.50,
      type: 'CREDIT',
      postedAt: DateTime.utc(2026, 5, 20, 9, 30),
    ),
    StatementItem(
      description: 'Pix enviado - Mercado Central',
      amount: -42.90,
      type: 'DEBIT',
      postedAt: DateTime.utc(2026, 5, 21, 14, 15),
    ),
  ];

  @override
  Future<CustomerProfile> loadProfile() async => _profile;

  @override
  Future<CustomerProfile> updateProfile(CustomerProfile profile) async {
    _profile = profile;
    return _profile;
  }

  String _correlationId() => 'corr-${Random().nextInt(900000) + 100000}';
}
