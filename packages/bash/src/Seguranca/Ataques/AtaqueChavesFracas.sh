# Busca dirigida de chaves fracas: chaves degeneradas/estruturadas não devem
# produzir keystream anômalo (repetição de blocos ou viés de bits).
# Complementa o ataque de chaves degeneradas, que só checa a saída do encrypt.
#
# Adaptação bash: 3 chaves (zeros, 0xFF, alternada AA/55) com keystream de 256
# bytes cada (o original usa 7 chaves de 2048 bytes).
AtaqueChavesFracas() {
    ATQ_NOME="Chaves fracas (busca dirigida)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho=$(( 256 * FBC_ESCALA ))
    local tolerancia_bits=0.05
    local chave_teste
    chave_teste=$(alvo_chave_de_teste)
    local tam_chave=${#chave_teste}

    local -a iv_fixo=()
    local i
    for (( i = 0; i < $(alvo_tamanho_iv); i++ )); do
        iv_fixo+=(0)
    done

    local -a nomes=("zeros" "0xFF" "alternada AA/55")
    local -a c_zeros=() c_ff=() c_aa55=()
    for (( i = 0; i < tam_chave; i++ )); do
        c_zeros+=(0)
        c_ff+=(255)
        if [ $(( i % 2 )) -eq 0 ]; then c_aa55+=(170); else c_aa55+=(85); fi
    done

    local -a casos=("${c_zeros[*]}" "${c_ff[*]}" "${c_aa55[*]}")

    local -a anomalias=()
    local idx
    for idx in "${!casos[@]}"; do
        local -a ks=()
        alvo_gerar_keystream_bruto ks "${casos[idx]}" "${iv_fixo[*]}" "101 110 99" "$tamanho"

        local -A blocos=()
        local repetidos=0
        local off
        for (( off = 0; off + 32 <= ${#ks[@]}; off += 32 )); do
            local hex
            hex=$(printf '%02x' "${ks[@]:off:32}")
            if [ -n "${blocos[$hex]+x}" ]; then
                repetidos=$(( repetidos + 1 ))
            else
                blocos[$hex]=1
            fi
        done

        local uns=0
        local b
        for b in "${ks[@]}"; do
            uns=$(( uns + $(util_contar_bits "$b") ))
        done
        local fracao_uns desvio_bits
        fracao_uns=$(util_div "$uns" $(( ${#ks[@]} * 8 )) 10)
        desvio_bits=$(awk -v f="$fracao_uns" 'BEGIN { d = f - 0.5; if (d < 0) d = -d; printf "%.6f", d }')

        if [ "$repetidos" -gt 0 ]; then
            anomalias+=("${nomes[idx]}: $repetidos bloco(s) repetido(s)")
        fi
        if util_maior "$desvio_bits" "$tolerancia_bits"; then
            anomalias+=("${nomes[idx]}: viés de bits $(util_pct "$fracao_uns" 1 1)%")
        fi
    done

    if [ "${#anomalias[@]}" -gt 0 ]; then
        local lista
        lista=$(printf '%s; ' "${anomalias[@]:0:5}")
        lista=${lista%; }
        res_vulneravel "Anomalias: $lista" "alta"
    else
        res_resistiu "Nenhuma das ${#casos[@]} chaves fracas produziu keystream anômalo ($tamanho bytes cada)" "info"
    fi
    return 0
}
