# AtaqueCusum
#
# Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
# passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
# pequeno que o monobit quase não vê faz o desvio acumulado crescer.
# Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.

AtaqueCusum() {
    ATQ_NOME="Somas cumulativas (cusum)"

    # PHP usava 8192 bytes; reduzido para caber no orçamento do bash.
    local tamanho=$(( 2048 * FBC_ESCALA ))
    local limiteZ=4.0

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a iv ks
    util_random_bytes iv "$(alvo_tamanho_iv)"
    alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho"

    local soma=0 maxAbs=0
    local i b byte bit abs
    for (( i = 0; i < ${#ks[@]}; i++ )); do
        byte=${ks[i]}
        for (( b = 7; b >= 0; b-- )); do
            bit=$(( (byte >> b) & 1 ))
            if [ "$bit" -eq 1 ]; then
                soma=$(( soma + 1 ))
            else
                soma=$(( soma - 1 ))
            fi
            abs=$(( soma < 0 ? -soma : soma ))
            if [ "$abs" -gt "$maxAbs" ]; then
                maxAbs=$abs
            fi
        done
    done

    local n=$(( ${#ks[@]} * 8 ))
    local z
    z=$(awk -v m="$maxAbs" -v n="$n" 'BEGIN { printf "%.2f", m / sqrt(n) }')

    local vulneravel=0
    if util_maior "$z" "$limiteZ"; then
        vulneravel=1
    fi

    local detalhes="max|S|=${maxAbs} sobre ${n} bits, max|S|/sqrt(n)=${z} (limite=${limiteZ})"
    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "media"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
