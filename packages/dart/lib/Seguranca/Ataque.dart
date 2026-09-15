import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';

/// Contrato de um ataque da suíte.
abstract class Ataque {
  String nome();

  /// Roda o ataque contra o alvo e retorna o resultado.
  /// Deve lançar [SkipAtaqueException] se o alvo não suportar os recursos
  /// necessários (ex: não expõe gerarKeystreamBruto).
  ResultadoAtaque executar(AlvoCriptografico alvo);
}
