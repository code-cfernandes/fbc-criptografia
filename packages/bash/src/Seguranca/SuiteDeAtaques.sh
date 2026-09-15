# Orquestra a execução de uma coleção de ataques contra o alvo.
#
# A lista global ATAQUES deve conter os nomes das funções de ataque, na ordem.
# Cada função preenche as globais ATQ_* (ver ResultadoAtaque.sh).

suite_rodar_e_imprimir() {
    local total=0 vulneraveis=0
    local ataque status

    echo "======================================================================"
    echo "RELATÓRIO DA SUÍTE DE ATAQUES"
    echo "======================================================================"
    echo

    for ataque in "${ATAQUES[@]}"; do
        ATQ_NOME=""
        ATQ_VULNERAVEL=0
        ATQ_SEVERIDADE="info"
        ATQ_DETALHES=""
        ATQ_SKIP=0
        ATQ_ERRO=0

        if "$ataque"; then
            :
        else
            ATQ_ERRO=1
            ATQ_DETALHES="código de retorno $?"
        fi

        if [ "${ATQ_SKIP:-0}" -eq 1 ]; then
            ATQ_VULNERAVEL=0
            ATQ_SEVERIDADE="pulado"
            ATQ_DETALHES="Pulado: $ATQ_DETALHES"
        elif [ "${ATQ_ERRO:-0}" -eq 1 ]; then
            ATQ_VULNERAVEL=1
            ATQ_SEVERIDADE="erro"
            ATQ_DETALHES="Erro ao executar: $ATQ_DETALHES"
        fi

        case "$ATQ_SEVERIDADE" in
            pulado) status="PULADO" ;;
            demonstracao) status="DEMONSTRAÇÃO" ;;
            *)
                if [ "$ATQ_VULNERAVEL" -eq 1 ]; then
                    status="❌ VULNERÁVEL"
                else
                    status="✅ resistiu"
                fi
                ;;
        esac

        printf '[%s] %s (%s): %s\n' "$status" "$ATQ_NOME" "$ATQ_SEVERIDADE" "$ATQ_DETALHES"

        if [ "$ATQ_VULNERAVEL" -eq 1 ] && [ "$ATQ_SEVERIDADE" != "pulado" ] && [ "$ATQ_SEVERIDADE" != "demonstracao" ]; then
            vulneraveis=$(( vulneraveis + 1 ))
        fi
        total=$(( total + 1 ))
    done

    echo
    echo "======================================================================"
    if [ "$vulneraveis" -eq 0 ]; then
        echo "RESUMO: nenhuma vulnerabilidade encontrada em $total ataque(s)."
    else
        echo "RESUMO: $vulneraveis vulnerabilidade(s) encontrada(s) de $total ataque(s) rodados!"
    fi
    echo "======================================================================"

    [ "$vulneraveis" -eq 0 ]
}
