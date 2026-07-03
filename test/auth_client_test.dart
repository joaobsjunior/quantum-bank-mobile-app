import 'package:test/test.dart';
import 'package:quantum_bank_mobile/features/auth/auth_client.dart';

void main() {
  test('AuthSession validity honours the expiry instant', () {
    final session = AuthSession(
      accessToken: 'token',
      subject: 'alice@quantumbank.local',
      expiresAt: DateTime.utc(2026, 5, 21, 10),
      scopes: const ['profile:read'],
    );

    expect(session.isValidAt(DateTime.utc(2026, 5, 21, 9)), isTrue);
    expect(session.isValidAt(DateTime.utc(2026, 5, 21, 11)), isFalse);
  });

  test('AuthException formats its code and message', () {
    expect(
      const AuthException(statusCode: 401, message: 'invalid').toString(),
      equals('AuthException(401): invalid'),
    );
  });
}
