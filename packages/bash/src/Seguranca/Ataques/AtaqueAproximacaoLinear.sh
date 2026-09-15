# Aproximação linear (criptoanálise de Matsui): procura por correlação entre
# bits de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
# aproximação linear com viés relevante; bias alto é uma pista explorável.
#
# Adaptação bash: ~20 amostras, apenas os 8 primeiros bits do IV e 16 bits de
# saída (o original usa 200 amostras, 128 bits de IV e 256 de saída). O limite
# foi recalibrado: com 20 amostras o desvio-padrão do viés é ~0.11, então o
# máximo sobre 128 pares chega naturalmente perto de 0.4.
AtaqueAproximacaoLinear() {
    ATQ_NOME="Aproximação linear (viés de Walsh)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local amostras=$(( 20 * FBC_ESCALA ))
    local bits_entrada=8
    local bits_saida=16
    local limite_bias=0.50
    local tamanho_bloco=32
    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)

    local -a entradas=()
    local -a saidas=()
    local s j
    for (( s = 0; s < amostras; s++ )); do
        local -a chave iv ks
        util_random_bytes chave 32
        util_random_bytes iv "$tamanho_iv"
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"

        local e="" o=""
        for (( j = 0; j < bits_entrada; j++ )); do
            local p=$(( j >> 3 ))
            local b=$(( 7 - (j & 7) ))
            e+=$(( (iv[p] >> b) & 1 ))
        done
        for (( j = 0; j < bits_saida; j++ )); do
            local p=$(( j >> 3 ))
            local b=$(( 7 - (j & 7) ))
            o+=$(( (ks[p] >> b) & 1 ))
        done
        entradas+=("$e")
        saidas+=("$o")
    done

    local maior_bias=0 par_i=-1 par_j=-1
    local i k
    for (( i = 0; i < bits_entrada; i++ )); do
        for (( k = 0; k < bits_saida; k++ )); do
            local iguais=0
            for (( s = 0; s < amostras; s++ )); do
                if [ "${entradas[s]:i:1}" = "${saidas[s]:k:1}" ]; then
                    iguais=$(( iguais + 1 ))
                fi
            done
            local bias
            bias=$(awk -v ig="$iguais" -v n="$amostras" 'BEGIN {
                b = ig / n - 0.5; if (b < 0) b = -b; printf "%.6f", b
            }')
            if util_maior "$bias" "$maior_bias"; then
                maior_bias=$bias
                par_i=$i
                par_j=$k
            fi
        done
    done

    local vulneravel=0
    if util_maior "$maior_bias" "$limite_bias"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="maior viés |p-0.5|=$(util_fmt 4 "$maior_bias") na aproximação IV[bit $par_i] -> saída[bit $par_j] (limite $(util_fmt 2 "$limite_bias")); $amostras amostras"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
