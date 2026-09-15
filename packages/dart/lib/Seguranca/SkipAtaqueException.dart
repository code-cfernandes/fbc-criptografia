/// Lançada quando o alvo não suporta os recursos que um ataque precisa.
class SkipAtaqueException implements Exception {
  final String message;

  SkipAtaqueException(this.message);

  @override
  String toString() => message;
}
