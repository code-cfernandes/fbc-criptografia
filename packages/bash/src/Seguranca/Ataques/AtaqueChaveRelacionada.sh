# Ataque de chave relacionada: chaves que diferem por um padrão fixo (1 bit,
# 0xFF, complemento) não devem gerar keystreams correlacionados. Um key
# schedule fraco faz keystream(key) e keystream(key ^ delta) compartilharem
# estrutura (distância de Hamming baixa).
#
# Adaptação bash: ~10 deltas (5 de 1 bit, 4 de 0xFF e o complemento) com 1 IV
# cada (o original usa 65 deltas com 3 IVs cada).
AtaqueChaveRelacionada() {
    ATQ_NOME="Chave relacionada (related-key)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho_bloco=32
    local iv_por_delta=$(( 1 * FBC_ESCALA ))
    local limite_media=0.45
    local limite_pior=0.30
    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)

    local -a chave_base
    string_to_bytes chave_base "$(alvo_chave_de_teste)"
    local len=${#chave_base[@]}
    local total_bits=$(( tamanho_bloco * 8 ))

    local -a deltas=()
    local i j
    for (( i = 0; i < 5; i++ )); do
        local -a d=()
        for (( j = 0; j < len; j++ )); do
            if [ "$j" -eq "$i" ]; then d+=(1); else d+=(0); fi
        done
        deltas+=("${d[*]}")
    done
    for (( i = 0; i < 4; i++ )); do
        local -a d=()
        for (( j = 0; j < len; j++ )); do
            if [ "$j" -eq "$i" ]; then d+=(255); else d+=(0); fi
        done
        deltas+=("${d[*]}")
    done
    local -a d_comp=()
    for (( j = 0; j < len; j++ )); do
        d_comp+=( $(( chave_base[j] ^ 255 )) )
    done
    deltas+=("${d_comp[*]}")

    local -a valores=()
    local di
    for (( di = 0; di < ${#deltas[@]}; di++ )); do
        local -a delta=(${deltas[di]})
        local -a chave_rel=()
        for (( j = 0; j < len; j++ )); do
            chave_rel+=( $(( chave_base[j] ^ delta[j] )) )
        done

        local q
        for (( q = 0; q < iv_por_delta; q++ )); do
            local -a iv=()
            util_random_bytes iv "$tamanho_iv"

            local -a ks1 ks2
            alvo_gerar_keystream_bruto ks1 "${chave_base[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"
            alvo_gerar_keystream_bruto ks2 "${chave_rel[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"

            local diff
            diff=$(util_bits_diferentes "${ks1[*]}" "${ks2[*]}")
            valores+=("$(util_div "$diff" "$total_bits" 6)")
        done
    done

    local n=${#valores[@]}
    local media
    media=$(printf '%s\n' "${valores[@]}" | awk '{ s += $1 } END { if (NR > 0) printf "%.10f", s / NR; else print "0" }')
    local pior=${valores[0]}
    local v
    for v in "${valores[@]}"; do
        if util_menor "$v" "$pior"; then
            pior=$v
        fi
    done

    local vulneravel=0
    if util_menor "$media" "$limite_media" || util_menor "$pior" "$limite_pior"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="média=$(util_pct "$media" 1 1)%, pior=$(util_pct "$pior" 1 1)% em $n pares (limites: média>=$(util_pct "$limite_media" 1 0)%, pior>=$(util_pct "$limite_pior" 1 0)%)"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
