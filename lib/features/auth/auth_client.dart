import 'package:flutter/foundation.dart';

@immutable
class AuthSession {
  const AuthSession({
    required this.accessToken,
    required this.subject,
    required this.expiresAt,
    required this.scopes,
  });

  final String accessToken;
  final String subject;
  final DateTime expiresAt;
  final List<String> scopes;

  bool isValidAt(DateTime now) => now.isBefore(expiresAt);
}

abstract interface class Authenticator {
  Future<AuthSession> authenticate();
}

class AuthException implements Exception {
  const AuthException({required this.statusCode, required this.message});

  final int statusCode;
  final String message;

  @override
  String toString() => 'AuthException($statusCode): $message';
}
