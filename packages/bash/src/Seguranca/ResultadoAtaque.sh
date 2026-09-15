# Resultado de um ataque e helpers que os ataques usam para preenchê-lo.
#
# Convenção: cada ataque define uma função com o nome da classe (ex.:
# AtaqueIdaEVolta) que preenche as globais:
#   ATQ_NOME         - nome de exibição do ataque
#   ATQ_VULNERAVEL   - 0 (resistiu) ou 1 (achou problema)
#   ATQ_SEVERIDADE   - critica|alta|media|baixa|info|demonstracao|pulado|erro
#   ATQ_DETALHES     - texto de uma linha
#   ATQ_SKIP         - 1 para marcar como "pulado"
#   ATQ_ERRO         - 1 para marcar como "erro"

res_resistiu() {
    ATQ_VULNERAVEL=0
    ATQ_SEVERIDADE="${2:-info}"
    ATQ_DETALHES="$1"
}

res_vulneravel() {
    ATQ_VULNERAVEL=1
    ATQ_SEVERIDADE="${2:-alta}"
    ATQ_DETALHES="$1"
}

res_demonstracao() {
    ATQ_VULNERAVEL=0
    ATQ_SEVERIDADE="demonstracao"
    ATQ_DETALHES="$1"
}

res_skip() {
    ATQ_SKIP=1
    ATQ_DETALHES="$1"
}

res_erro() {
    ATQ_ERRO=1
    ATQ_DETALHES="$1"
}
