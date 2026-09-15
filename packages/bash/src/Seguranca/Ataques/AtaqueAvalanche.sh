# Mudar 1 bit do IV deveria, em média, mudar ~50% dos bits do keystream
# gerado (efeito avalanche). Números muito abaixo disso indicam difusão
# fraca - foi o que achamos quando o número de rodadas de mistura era
# baixo demais numa das versões anteriores.
AtaqueAvalanche() {
    ATQ_NOME="Efeito avalanche"

    # Reduzido de 3000 para ~50 amostras (bash é ordens de magnitude mais lento).
    local amostras=$(( 50 * FBC_ESCALA ))
    local tamanho_bloco=32
    local limite_media=0.45
    local limite_pior_caso=0.30
    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)

    local -a chave=()
    string_to_bytes chave "$(alvo_chave_de_teste)"
    local chave_str="${chave[*]}"

    local -a primeiro=()
    local -a iv_seed=()
    util_random_bytes iv_seed "$tamanho_iv"
    alvo_gerar_keystream_bruto primeiro "$chave_str" "${iv_seed[*]}" "enc" "$tamanho_bloco"
    if [ ${#primeiro[@]} -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a valores=()
    local t
    for (( t = 0; t < amostras; t++ )); do
        local -a iv1=()
        local -a iv2=()
        util_random_bytes iv1 "$tamanho_iv"
        iv2=("${iv1[@]}")
        local pos bit
        pos=$(util_random_int 0 $(( tamanho_iv - 1 )))
        bit=$(( 1 << $(util_random_int 0 7) ))
        iv2[pos]=$(( iv2[pos] ^ bit ))

        local -a ks1=()
        local -a ks2=()
        alvo_gerar_keystream_bruto ks1 "$chave_str" "${iv1[*]}" "enc" "$tamanho_bloco"
        alvo_gerar_keystream_bruto ks2 "$chave_str" "${iv2[*]}" "enc" "$tamanho_bloco"

        local diff
        diff=$(util_bits_diferentes "${ks1[*]}" "${ks2[*]}")
        valores+=("$(util_div "$diff" $(( tamanho_bloco * 8 )) 6)")
    done

    local ordenado
    ordenado=$(printf '%s\n' "${valores[@]}" | sort -g)
    local -a vals=($ordenado)
    local n=${#vals[@]}
    local media
    media=$(printf '%s\n' "${vals[@]}" | awk '{ s += $1 } END { if (NR > 0) printf "%.10f", s / NR; else print "0" }')
    local pior=${vals[0]}
    local idx_p1
    idx_p1=$(awk -v n="$n" 'BEGIN { printf "%d", int(n * 0.01) }')
    local p1=${vals[$idx_p1]}

    local vulneravel=0
    if util_menor "$media" "$limite_media" || util_menor "$pior" "$limite_pior_caso"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="média=$(util_pct "$media" 1 1)%, pior caso=$(util_pct "$pior" 1 1)%, percentil 1%=$(util_pct "$p1" 1 1)% (limites: média>=$(util_pct "$limite_media" 1 0)%, pior>=$(util_pct "$limite_pior_caso" 1 0)%)"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
