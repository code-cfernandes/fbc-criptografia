# Fold estrutural (metades/quartos/oitavos repetidos).
#
# Esse é o ataque que pegou o bug mais sério que encontramos: quando a
# distância de mistura era exatamente metade do bloco, TODOS os IVs
# aleatórios produziam um bloco cuja primeira metade era idêntica à segunda.
# Testa repetição em frações de 1/2, 1/4 e 1/8 do bloco.
#
# Adaptação bash: amostras reduzidas de 5000 para 500 (× FBC_ESCALA) - bash é
# ordens de magnitude mais lento. O keystream é comparado como array de
# decimais (strings separadas por espaço), nunca como bytes crus.

AtaqueFoldEstrutural() {
    ATQ_NOME="Fold estrutural (metades/quartos/oitavos repetidos)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local amostras=$(( 500 * FBC_ESCALA ))
    local tamanho_bloco=32

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a primeiro=() ks=() fatia=() primeira_fatia=()
    local iv

    util_random_bytes iv 16
    alvo_gerar_keystream_bruto primeiro "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a divisores=()
    local d
    for d in 2 4 8 16; do
        if [ $(( tamanho_bloco % d )) -eq 0 ] && [ $(( tamanho_bloco / d )) -ge 1 ]; then
            divisores+=("$d")
        fi
    done

    declare -A ocorrencias=()
    for d in "${divisores[@]}"; do
        ocorrencias[$d]=0
    done

    # Limite de "ruído esperado" por acaso: pra fatias de $tam bytes,
    # a chance de colisão por acaso é ~1/256^tam por par comparado -
    # desprezível para tam >= 2, então qualquer contagem > 0 já é
    # suspeita o bastante pra investigar (ajustamos a margem pra
    # fatias de 1-2 bytes, onde colisão por acaso é mais provável).
    local i j div tam_fatia
    for (( i = 0; i < amostras; i++ )); do
        util_random_bytes iv 16
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"
        for div in "${divisores[@]}"; do
            tam_fatia=$(( tamanho_bloco / div ))
            primeira_fatia=("${ks[@]:0:tam_fatia}")
            for (( j = 1; j < div; j++ )); do
                fatia=("${ks[@]:$(( j * tam_fatia )):tam_fatia}")
                if [ "${fatia[*]}" = "${primeira_fatia[*]}" ]; then
                    ocorrencias[$div]=$(( ${ocorrencias[$div]} + 1 ))
                    break
                fi
            done
        done
    done

    local -a problemas=()
    local margem
    for div in "${divisores[@]}"; do
        if [ $(( tamanho_bloco / div )) -le 2 ]; then
            margem=$(( (amostras * 1) / 100 + 3 ))
        else
            margem=5
        fi
        if [ "${ocorrencias[$div]}" -gt "$margem" ]; then
            problemas+=("1/$div do bloco repetido em ${ocorrencias[$div]}/$amostras")
        fi
    done

    if [ "${#problemas[@]}" -gt 0 ]; then
        local detalhe
        detalhe=$(printf '%s, ' "${problemas[@]}")
        detalhe=${detalhe%, }
        res_vulneravel "$detalhe" "critica"
        return 0
    fi

    local resumo="" sep=""
    for div in "${divisores[@]}"; do
        resumo+="${sep}\"$div\":${ocorrencias[$div]}"
        sep=","
    done
    res_resistiu "Nenhuma repetição estrutural acima do ruído esperado: {$resumo}" "info"
    return 0
}
