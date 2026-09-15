# Complemento do AtaqueCoberturaDependencia (que varia a CHAVE): aqui varia
# o IV. Toda posição do IV precisa influenciar toda posição de saída; uma
# posição "morta" do IV reduziria a entropia efetiva que o IV injeta.
#
# Amostra reduzida para bash: bloco de 8 bytes e poucas perturbações por
# posição, multiplicadas por FBC_ESCALA.

AtaqueCoberturaDependenciaIV() {
    ATQ_NOME="Cobertura de dependência do IV (entrada x saída)"

    local tamanho_bloco=8
    local perturbacoes=$(( 2 * FBC_ESCALA ))
    local tamanho_iv=16

    local -a prop_arr
    string_to_bytes prop_arr "enc"
    local prop="${prop_arr[*]}"

    local -a chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a iv_base=()
    local i
    for (( i = 0; i < tamanho_iv; i++ )); do
        iv_base+=(0)
    done

    local -a ks_base
    alvo_gerar_keystream_bruto ks_base "${chave[*]}" "${iv_base[*]}" "$prop" "$tamanho_bloco"

    local pares="" qtd=0
    local pos_iv p pos_saida
    for (( pos_iv = 0; pos_iv < tamanho_iv; pos_iv++ )); do
        local -a afetou=()
        for (( pos_saida = 0; pos_saida < tamanho_bloco; pos_saida++ )); do
            afetou+=(0)
        done

        for (( p = 0; p < perturbacoes; p++ )); do
            local -a iv=("${iv_base[@]}")
            iv[pos_iv]=$(util_random_int 1 255)
            local -a ks
            alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "$prop" "$tamanho_bloco"

            for (( pos_saida = 0; pos_saida < tamanho_bloco; pos_saida++ )); do
                if [ "${ks[pos_saida]}" != "${ks_base[pos_saida]}" ]; then
                    afetou[pos_saida]=1
                fi
            done
        done

        for (( pos_saida = 0; pos_saida < tamanho_bloco; pos_saida++ )); do
            if [ "${afetou[pos_saida]}" -eq 0 ]; then
                pares+="iv[$pos_iv] -> saida[$pos_saida]; "
                qtd=$(( qtd + 1 ))
            fi
        done
    done

    if [ "$qtd" -gt 0 ]; then
        res_vulneravel "$qtd par(es) sem dependência detectável em $perturbacoes tentativas cada" alta
    else
        res_resistiu "Todas as $tamanho_iv posições do IV influenciam todas as $tamanho_bloco posições de saída"
    fi
    return 0
}
