# Verifica, byte a byte, se toda posição de SAÍDA depende de toda posição
# de ENTRADA (mudando 1 byte da chave, com várias perturbações diferentes
# pra evitar falso-positivo por coincidência de valor). Uma dependência
# ausente indica que a mistura não se propagou completamente - um atacante
# poderia isolar e atacar aquele par de posições separadamente do resto.
#
# Amostra reduzida para bash: matriz 8x8 (em vez de 32x32) e poucas
# perturbações por par, multiplicadas por FBC_ESCALA.

AtaqueCoberturaDependencia() {
    ATQ_NOME="Cobertura de dependência (matriz entrada x saída)"

    local tamanho=8
    local perturbacoes=$(( 2 * FBC_ESCALA ))

    local -a prop_arr
    string_to_bytes prop_arr "enc"
    local prop="${prop_arr[*]}"

    local -a chave_base=()
    local i
    for (( i = 0; i < tamanho; i++ )); do
        chave_base+=(0)
    done

    local -a iv
    util_random_bytes iv 16

    local -a ks_base
    alvo_gerar_keystream_bruto ks_base "${chave_base[*]}" "${iv[*]}" "$prop" "$tamanho"

    local pares="" qtd=0
    local pos_entrada p pos_saida
    for (( pos_entrada = 0; pos_entrada < tamanho; pos_entrada++ )); do
        local -a afetou=()
        for (( pos_saida = 0; pos_saida < tamanho; pos_saida++ )); do
            afetou+=(0)
        done

        for (( p = 0; p < perturbacoes; p++ )); do
            local -a chave_teste=("${chave_base[@]}")
            chave_teste[pos_entrada]=$(util_random_int 1 255)
            local -a ks
            alvo_gerar_keystream_bruto ks "${chave_teste[*]}" "${iv[*]}" "$prop" "$tamanho"

            for (( pos_saida = 0; pos_saida < tamanho; pos_saida++ )); do
                if [ "${ks[pos_saida]}" != "${ks_base[pos_saida]}" ]; then
                    afetou[pos_saida]=1
                fi
            done
        done

        for (( pos_saida = 0; pos_saida < tamanho; pos_saida++ )); do
            if [ "${afetou[pos_saida]}" -eq 0 ]; then
                pares+="entrada[$pos_entrada] -> saída[$pos_saida]; "
                qtd=$(( qtd + 1 ))
            fi
        done
    done

    if [ "$qtd" -gt 0 ]; then
        res_vulneravel "$qtd par(es) sem dependência detectável em $perturbacoes tentativas cada" media
    else
        res_resistiu "Todos os $(( tamanho * tamanho )) pares (entrada, saída) mostraram dependência"
    fi
    return 0
}
