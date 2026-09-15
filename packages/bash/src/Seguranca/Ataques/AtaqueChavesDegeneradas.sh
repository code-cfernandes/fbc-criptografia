# Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
# (tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
# produzir keystream degenerado - e aqui testamos no pior cenário, com IV
# zerado junto, pra isolar a contribuição da chave.

AtaqueChavesDegeneradas() {
    ATQ_NOME="Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)"

    local tamanho_bloco=32
    local chave_str
    chave_str=$(alvo_chave_de_teste)
    local tam_chave=${#chave_str}
    local -a iv_zero=()
    local -a c_zero=() c_ff=() c_aa=() c_55=() c_a=() c_cresc=()
    local i
    for (( i = 0; i < tam_chave; i++ )); do
        iv_zero+=(0)
        c_zero+=(0)
        c_ff+=(255)
        c_aa+=(170)
        c_55+=(85)
        c_a+=(65)
        c_cresc+=($(( i % 256 )))
    done

    local -a prop_arr
    string_to_bytes prop_arr "enc"
    local prop="${prop_arr[*]}"
    local iv_str="${iv_zero[*]}"

    # gera o primeiro keystream só pra confirmar que a camada está exposta
    local -a chave_bytes primeiro
    string_to_bytes chave_bytes "$chave_str"
    alvo_gerar_keystream_bruto primeiro "${chave_bytes[*]}" "$iv_str" "$prop" "$tamanho_bloco"

    local -a nomes=("zero" "0xFF" "alternada 0xAA" "alternada 0x55" "repetida \"A\"" "crescente")
    local -a casos=("${c_zero[*]}" "${c_ff[*]}" "${c_aa[*]}" "${c_55[*]}" "${c_a[*]}" "${c_cresc[*]}")

    local problemas="" qtd=0 idx
    for idx in "${!casos[@]}"; do
        local -a ks
        alvo_gerar_keystream_bruto ks "${casos[idx]}" "$iv_str" "$prop" "$tamanho_bloco"

        local metade=$(( tamanho_bloco / 2 ))
        local periodico=1 j
        for (( j = 0; j < metade; j++ )); do
            if [ "${ks[j]}" != "${ks[j + metade]}" ]; then
                periodico=0
                break
            fi
        done

        local -A uniq=()
        local b
        for b in "${ks[@]}"; do
            uniq[$b]=1
        done
        local bytes_unicos=${#uniq[@]}

        if [ "$periodico" -eq 1 ] || [ "$bytes_unicos" -lt "$metade" ]; then
            qtd=$(( qtd + 1 ))
            local per_txt="não"
            if [ "$periodico" -eq 1 ]; then per_txt="sim"; fi
            problemas+="${nomes[idx]} (periódico=$per_txt, bytes únicos=$bytes_unicos/$tamanho_bloco); "
        fi
    done

    if [ "$qtd" -gt 0 ]; then
        res_vulneravel "${problemas%; }" alta
    else
        res_resistiu "Nenhuma das ${#casos[@]} chaves degeneradas testadas produziu saída anômala"
    fi
    return 0
}
