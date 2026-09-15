# BIC (Bit Independence Criterion): pares de bits de saída não devem estar
# correlacionados quando a entrada muda. Para cada amostra, vira 1 bit do IV e
# registra quais bits de saída mudaram; depois mede a correlação (phi) entre
# cada par de bits de saída. Pares muito correlacionados indicam difusão
# acoplada (um bit "carrega" informação sobre outro).
#
# Adaptação bash: ~50 amostras (o original usa 300) e apenas os primeiros 8
# bytes (64 bits) de saída. O limite de |phi| foi recalibrado para o tamanho
# reduzido da amostra: com n=50 o desvio-padrão de phi é ~1/sqrt(n), então o
# máximo sobre ~2000 pares chega naturalmente perto de 0.5.
AtaqueBIC() {
    ATQ_NOME="BIC (Bit Independence Criterion)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho_bloco=8
    local amostras=$(( 50 * FBC_ESCALA ))
    local limite=0.70
    local total_bits=$(( tamanho_bloco * 8 ))
    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)

    local -a chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a amostras_flips=()
    local s j
    for (( s = 0; s < amostras; s++ )); do
        local -a iv1 iv2 ks1 ks2
        util_random_bytes iv1 "$tamanho_iv"
        iv2=("${iv1[@]}")
        local pos bit
        pos=$(util_random_int 0 $(( tamanho_iv - 1 )))
        bit=$(util_random_int 0 7)
        iv2[pos]=$(( iv2[pos] ^ (1 << bit) ))

        alvo_gerar_keystream_bruto ks1 "${chave[*]}" "${iv1[*]}" "101 110 99" "$tamanho_bloco"
        alvo_gerar_keystream_bruto ks2 "${chave[*]}" "${iv2[*]}" "101 110 99" "$tamanho_bloco"

        local f=""
        for (( j = 0; j < total_bits; j++ )); do
            local p=$(( j >> 3 ))
            local b=$(( 7 - (j & 7) ))
            local b1=$(( (ks1[p] >> b) & 1 ))
            local b2=$(( (ks2[p] >> b) & 1 ))
            if [ "$b1" -ne "$b2" ]; then
                f+="1"
            else
                f+="0"
            fi
        done
        amostras_flips+=("$f")
    done

    local pior_phi=0 pior_a=-1 pior_b=-1
    local a b
    for (( a = 0; a < total_bits; a++ )); do
        for (( b = a + 1; b < total_bits; b++ )); do
            local n11=0 n10=0 n01=0 n00=0
            for (( s = 0; s < amostras; s++ )); do
                local fa=${amostras_flips[s]:a:1}
                local fb=${amostras_flips[s]:b:1}
                if [ "$fa" = "1" ] && [ "$fb" = "1" ]; then
                    n11=$(( n11 + 1 ))
                elif [ "$fa" = "1" ]; then
                    n10=$(( n10 + 1 ))
                elif [ "$fb" = "1" ]; then
                    n01=$(( n01 + 1 ))
                else
                    n00=$(( n00 + 1 ))
                fi
            done

            local phi
            phi=$(awk -v n11="$n11" -v n10="$n10" -v n01="$n01" -v n00="$n00" 'BEGIN {
                den = sqrt((n11+n10)*(n01+n00)*(n11+n01)*(n10+n00));
                if (den > 0) p = (n11*n00 - n10*n01) / den; else p = 0;
                printf "%.6f", p
            }')
            local abs_phi
            abs_phi=$(awk -v p="$phi" 'BEGIN { if (p < 0) p = -p; printf "%.6f", p }')
            if util_maior "$abs_phi" "$pior_phi"; then
                pior_phi=$abs_phi
                pior_a=$a
                pior_b=$b
            fi
        done
    done

    local vulneravel=0
    if util_maior "$pior_phi" "$limite"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="maior |phi|=$(util_fmt 3 "$pior_phi") entre bits de saída [$pior_a, $pior_b] (limite $(util_fmt 2 "$limite")); $amostras amostras"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
