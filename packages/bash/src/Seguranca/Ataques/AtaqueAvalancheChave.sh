# O AtaqueAvalanche mede a difusão de 1 bit do IV; esse faz o mesmo com a
# CHAVE. É o teste mais direto de "a chave está de fato sendo misturada por
# inteiro": mudar 1 bit da chave deveria mudar ~50% dos bits do keystream.
# Números baixos indicam que parte da chave tem pouca influência - o que
# reduziria o espaço de busca de um atacante.
AtaqueAvalancheChave() {
    ATQ_NOME="Efeito avalanche da chave"

    # Reduzido de 3000 para ~50 amostras (bash é ordens de magnitude mais lento).
    local amostras=$(( 50 * FBC_ESCALA ))
    local tamanho_bloco=32
    local limite_media=0.45
    local limite_pior_caso=0.30

    local -a chave_base=()
    string_to_bytes chave_base "$(alvo_chave_de_teste)"
    local len_chave=${#chave_base[@]}
    local chave_base_str="${chave_base[*]}"

    local -a iv=()
    util_random_bytes iv "$(alvo_tamanho_iv)"

    local -a primeiro=()
    alvo_gerar_keystream_bruto primeiro "$chave_base_str" "${iv[*]}" "enc" "$tamanho_bloco"
    if [ ${#primeiro[@]} -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a valores=()
    local t
    for (( t = 0; t < amostras; t++ )); do
        local -a chave=("${chave_base[@]}")
        local pos bit
        pos=$(util_random_int 0 $(( len_chave - 1 )))
        bit=$(( 1 << $(util_random_int 0 7) ))
        chave[pos]=$(( chave[pos] ^ bit ))

        local -a ks1=()
        local -a ks2=()
        alvo_gerar_keystream_bruto ks1 "$chave_base_str" "${iv[*]}" "enc" "$tamanho_bloco"
        alvo_gerar_keystream_bruto ks2 "${chave[*]}" "${iv[*]}" "enc" "$tamanho_bloco"

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

    local vulneravel=0
    if util_menor "$media" "$limite_media" || util_menor "$pior" "$limite_pior_caso"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="média=$(util_pct "$media" 1 1)%, pior caso=$(util_pct "$pior" 1 1)% (limites: média>=$(util_pct "$limite_media" 1 0)%, pior>=$(util_pct "$limite_pior_caso" 1 0)%)"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
