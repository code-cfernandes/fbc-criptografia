/// Severidade de um resultado de ataque.
enum Severidade {
  critica,
  alta,
  media,
  baixa,
  info,
  pulado,
  demonstracao,
  erro,
}

/// Resultado de rodar um ataque contra um alvo.
///
/// `vulneravel = true` significa que o ataque ACHOU um problema (a cifra
/// falhou). `vulneravel = false` significa que a cifra resistiu a esse ataque
/// específico.
class ResultadoAtaque {
  final String nomeAtaque;
  final bool vulneravel;
  final Severidade severidade;
  final String detalhes;
  final Map<String, dynamic>? dados;

  ResultadoAtaque(
    this.nomeAtaque,
    this.vulneravel,
    this.severidade,
    this.detalhes, [
    this.dados,
  ]);

  String linhaResumo() {
    final String status;
    if (severidade == Severidade.pulado) {
      status = 'PULADO';
    } else if (severidade == Severidade.demonstracao) {
      status = 'DEMONSTRAÇÃO';
    } else {
      status = vulneravel ? '❌ VULNERÁVEL' : '✅ resistiu';
    }

    return '[$status] $nomeAtaque (${severidade.name}): $detalhes';
  }
}
