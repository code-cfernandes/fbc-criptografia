# IVs degenerados (zero, 0xFF, alternado).
#
# Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
# (tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada
# mesmo quando a maioria das entradas se comporta bem. Testa especificamente
# esses casos extremos, que testes com entrada aleatória raramente cobrem.
#
# Adaptação bash: os IVs vivem em arrays de decimais (podem ter 0x00), então
# nenhum caso precisa ser descartado.

AtaqueIVsDegenerados() {
    ATQ_NOME="IVs degenerados (zero, 0xFF, alternado)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"
    local tam_iv=16
    local tamanho_bloco=32

    local -a primeiro=() ks=() iv=() m1=() m2=()
    local i
    local -a iv_zero=() iv_ff=() iv_aa=() iv_55=() iv_cres=()
    for (( i = 0; i < tam_iv; i++ )); do
        iv_zero+=(0)
        iv_ff+=(255)
        iv_aa+=(170)
        iv_55+=(85)
        iv_cres+=("$i")
    done

    alvo_gerar_keystream_bruto primeiro "${chave[*]}" "${iv_zero[*]}" "101 110 99" "$tamanho_bloco"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a nomes=("zero" "0xFF" "alternado 0xAA" "alternado 0x55" "crescente")
    local -a ivs=("${iv_zero[*]}" "${iv_ff[*]}" "${iv_aa[*]}" "${iv_55[*]}" "${iv_cres[*]}")

    local problemas=""
    local nome idx b metade periodico pouca per_txt bytes_unicos
    for idx in "${!nomes[@]}"; do
        nome=${nomes[$idx]}
        iv=(${ivs[$idx]})

        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"

        metade=$(( tamanho_bloco / 2 ))
        m1=("${ks[@]:0:metade}")
        m2=("${ks[@]:metade:metade}")
        periodico=0
        if [ "${m1[*]}" = "${m2[*]}" ]; then
            periodico=1
        fi

        local -A uniq=()
        for b in "${ks[@]}"; do
            uniq[$b]=1
        done
        bytes_unicos=${#uniq[@]}
        pouca=0
        if [ "$bytes_unicos" -lt "$(( tamanho_bloco / 2 ))" ]; then
            pouca=1
        fi

        if [ "$periodico" -eq 1 ] || [ "$pouca" -eq 1 ]; then
            per_txt="não"
            if [ "$periodico" -eq 1 ]; then
                per_txt="sim"
            fi
            problemas+="$nome (periódico=$per_txt, bytes únicos=$bytes_unicos/$tamanho_bloco); "
        fi
    done

    if [ -n "$problemas" ]; then
        problemas=${problemas%; }
        res_vulneravel "$problemas" "alta"
        return 0
    fi

    res_resistiu "Nenhum dos ${#nomes[@]} IVs degenerados testados produziu saída anômala" "info"
    return 0
}
