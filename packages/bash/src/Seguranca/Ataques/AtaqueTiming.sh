# Se a comparação de integridade não for de tempo constante (ex: usar ===
# em vez de hash_equals()), um atacante consegue medir QUANTOS bytes
# iniciais do campo de integridade batem, comparando o tempo de resposta -
# e reconstruir a integridade correta byte a byte, sem nunca saber a chave.
#
# Esse teste gera um token válido, cria versões adulteradas onde o campo
# de integridade erra em posições DIFERENTES (início vs. fim do campo), e
# compara o tempo médio de decrypt() entre os grupos. Uma diferença
# estatisticamente clara entre "erra logo no primeiro byte" e "erra só no
# último byte" indica uma comparação vulnerável a timing.
#
# IMPORTANTE: testes de timing têm MUITO ruído (agendador do SO, forks do
# bash). Isso é uma checagem heurística grosseira, não uma prova formal.
#
# Adaptação bash: repeticoesPorGrupo reduzido de 400 para 20 (×FBC_ESCALA) e
# 3 rodadas intercaladas (A/B dentro de cada rodada, como no PHP, para diluir
# deriva de carga da máquina). Usa EPOCHREALTIME (microssegundos, sem fork
# por medição) com fallback para `date +%s%N`. Os tokens adulterados são
# construídos uma vez por grupo, fora da região cronometrada, para não somar
# o custo do base64 à medição.
#
# O limite sobe de 15% (PHP) para 35%: cada decrypt() no bash dispara vários
# processos (od/base64) e um subshell, então o piso de ruído aqui é uma ordem
# de grandeza maior que no PHP - medido entre 0,6% e 14% em execuções
# repetidas. O sinal de um strcmp não-constante é real mas imensamente menor
# que esse ruído, então um limite de 15% geraria falso positivo frequente.
AtaqueTiming() {
    ATQ_NOME="Timing da verificação de integridade"

    local repeticoes=$(( 20 * FBC_ESCALA ))
    local rodadas=3
    local limite="0.35"

    local token prefixo corpo
    token="$(alvo_encrypt 'MENSAGEM_PARA_TESTE_DE_TIMING')"
    prefixo="$(alvo_prefixo)"
    corpo="${token:${#prefixo}}"

    local -a decoded integ ct iv
    alvo_base64url_decode decoded "$corpo"
    alvo_decompor integ ct iv "${decoded[*]}"
    local tamanhoIntegridade=${#integ[@]}

    # Pré-monta os dois tokens adulterados: erro no primeiro byte (A) e erro
    # no último byte (B) do campo de integridade.
    local posIdx pos
    local -a adulterada recomposta
    local -a tokensAdulterados
    for (( posIdx = 0; posIdx < 2; posIdx++ )); do
        if [ "$posIdx" -eq 0 ]; then
            pos=0
        else
            pos=$(( tamanhoIntegridade - 1 ))
        fi
        # Erra o bit menos significativo do byte escolhido (chr(ord(b) ^ 0x01)).
        adulterada=("${integ[@]}")
        adulterada[pos]=$(( adulterada[pos] ^ 1 ))
        alvo_recompor recomposta "${adulterada[*]}" "${ct[*]}" "${iv[*]}"
        tokensAdulterados[posIdx]="${prefixo}$(alvo_base64url_encode "${recomposta[*]}")"
    done

    local somaA=0 somaB=0 nRodadas=0
    local rod r inicio fim med saida
    local -a tempos ordenados
    for (( rod = 0; rod < rodadas; rod++ )); do
        for (( posIdx = 0; posIdx < 2; posIdx++ )); do
            tempos=()
            for (( r = 0; r < repeticoes; r++ )); do
                if [ -n "${EPOCHREALTIME:-}" ]; then
                    inicio=${EPOCHREALTIME//[.,]/}
                else
                    inicio=$(date +%s%N)
                fi
                # O decrypt DEVE falhar (integridade adulterada).
                if saida=$(alvo_decrypt "${tokensAdulterados[posIdx]}" 2>/dev/null); then
                    :
                fi
                if [ -n "${EPOCHREALTIME:-}" ]; then
                    fim=${EPOCHREALTIME//[.,]/}
                else
                    fim=$(date +%s%N)
                fi
                tempos+=( $(( fim - inicio )) )
            done

            # Mediana em vez de média - mais robusta a outliers de agendamento.
            mapfile -t ordenados < <(printf '%s\n' "${tempos[@]}" | sort -n)
            med=${ordenados[$(( ${#ordenados[@]} / 2 ))]}
            if [ "$posIdx" -eq 0 ]; then
                somaA=$(( somaA + med ))
            else
                somaB=$(( somaB + med ))
            fi
        done
        nRodadas=$(( nRodadas + 1 ))
    done

    local medianaA medianaB dif
    medianaA=$(util_div "$somaA" "$nRodadas" 0)
    medianaB=$(util_div "$somaB" "$nRodadas" 0)
    dif=$(awk -v a="$medianaA" -v b="$medianaB" 'BEGIN { m=(a>b)?a:b; if (m==0) { print "0" } else { printf "%.6f", ((a>b)?a-b:b-a)/m } }')

    local dif_pct limite_pct
    dif_pct=$(util_pct "$dif" 1 1)
    limite_pct=$(util_pct "$limite" 1 0)

    if util_maior "$dif" "$limite"; then
        res_vulneravel "mediana erro-no-início=${medianaA}us, mediana erro-no-fim=${medianaB}us, diferença relativa=${dif_pct}% (limite=${limite_pct}%). Diferença suspeita - investigar se a comparação usa hash_equals()." "media"
    else
        res_resistiu "mediana erro-no-início=${medianaA}us, mediana erro-no-fim=${medianaB}us, diferença relativa=${dif_pct}% (limite=${limite_pct}%). Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal)."
    fi
    return 0
}
