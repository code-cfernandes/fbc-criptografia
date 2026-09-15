# SAC (Strict Avalanche Criterion): para CADA bit de entrada (IV), ao virar
# esse bit, CADA bit de saída deve mudar com probabilidade ~0.5. Mede o pior
# bit de saída; se algum fica longe de 50%, a difusão tem ponto cego.
#
# Adaptação bash: apenas 4 posições do IV, 8 bits por posição e 2 amostras
# (cada amostra contribui para todos os 256 bits de saída, então cada bit
# acumula 64 observações). A tolerância foi calibrada para esse tamanho de
# amostra (o ruído binomial com 64 observações é bem maior que os 0.05 do
# original, que usava 5120 observações por bit).
AtaqueSAC() {
    ATQ_NOME="SAC (Strict Avalanche Criterion)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho_bloco=32
    local posicoes=4
    local amostras=$(( 2 * FBC_ESCALA ))
    local tolerancia=0.40

    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)
    if [ "$posicoes" -gt "$tamanho_iv" ]; then
        posicoes=$tamanho_iv
    fi

    local total_bits=$(( tamanho_bloco * 8 ))
    local -a flips=()
    local j
    for (( j = 0; j < total_bits; j++ )); do
        flips[j]=0
    done

    local -a chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local total=0 pos bit s
    for (( pos = 0; pos < posicoes; pos++ )); do
        for (( bit = 0; bit < 8; bit++ )); do
            for (( s = 0; s < amostras; s++ )); do
                local -a iv1 iv2 ks1 ks2
                util_random_bytes iv1 "$tamanho_iv"
                iv2=("${iv1[@]}")
                iv2[pos]=$(( iv2[pos] ^ (1 << bit) ))

                alvo_gerar_keystream_bruto ks1 "${chave[*]}" "${iv1[*]}" "101 110 99" "$tamanho_bloco"
                alvo_gerar_keystream_bruto ks2 "${chave[*]}" "${iv2[*]}" "101 110 99" "$tamanho_bloco"

                for (( j = 0; j < total_bits; j++ )); do
                    local p=$(( j >> 3 ))
                    local b=$(( 7 - (j & 7) ))
                    local b1=$(( (ks1[p] >> b) & 1 ))
                    local b2=$(( (ks2[p] >> b) & 1 ))
                    if [ "$b1" -ne "$b2" ]; then
                        flips[j]=$(( flips[j] + 1 ))
                    fi
                done
                total=$(( total + 1 ))
            done
        done
    done

    local pior=-1 pior_desvio=0 pior_p=0.5
    for (( j = 0; j < total_bits; j++ )); do
        local p desvio
        p=$(util_div "${flips[j]}" "$total" 6)
        desvio=$(awk -v p="$p" 'BEGIN { d = p - 0.5; if (d < 0) d = -d; printf "%.6f", d }')
        if util_maior "$desvio" "$pior_desvio"; then
            pior_desvio=$desvio
            pior=$j
            pior_p=$p
        fi
    done

    local vulneravel=0
    if util_maior "$pior_desvio" "$tolerancia"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="pior bit de saída=$pior: p=$(util_pct "$pior_p" 1 2)% (esperado 50%, tolerância ±$(util_pct "$tolerancia" 1 1)%); $total amostras por bit de entrada"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
