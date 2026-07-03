import 'package:test/test.dart';
import 'package:quantum_bank_mobile/core/api/gateway_api.dart';

void main() {
  test('CustomerProfile.copyWith overrides fields but keeps the document number', () {
    const profile = CustomerProfile(
      fullName: 'Alice',
      email: 'alice@quantumbank.local',
      phone: '+55 71 90000-0001',
      documentNumber: '123.456.789-00',
      address: 'Av. Oceano Seguro, 100',
    );

    final updated = profile.copyWith(
      fullName: 'Alice Updated',
      email: 'alice.updated@quantumbank.local',
      phone: '+55 71 90000-0002',
      address: 'Rua Nova, 200',
    );

    expect(updated.fullName, equals('Alice Updated'));
    expect(updated.email, equals('alice.updated@quantumbank.local'));
    expect(updated.phone, equals('+55 71 90000-0002'));
    expect(updated.address, equals('Rua Nova, 200'));
    expect(updated.documentNumber, equals('123.456.789-00'));
  });

  test('CustomerProfile.copyWith keeps existing fields when omitted', () {
    const profile = CustomerProfile(
      fullName: 'Alice',
      email: 'alice@quantumbank.local',
      phone: '+55 71 90000-0001',
      documentNumber: '123.456.789-00',
      address: 'Av. Oceano Seguro, 100',
    );

    final unchanged = profile.copyWith();

    expect(unchanged.fullName, equals('Alice'));
    expect(unchanged.email, equals('alice@quantumbank.local'));
    expect(unchanged.phone, equals('+55 71 90000-0001'));
    expect(unchanged.address, equals('Av. Oceano Seguro, 100'));
  });
}
