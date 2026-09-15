# Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
# primeira metade do keystream e mede a taxa de acerto na segunda metade.
# Para um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
# Qualquer coisa acima disso indica que os bits carregam dependência
# explorável - o embrião de um ataque de predição de estado.
#
# Adaptação bash: amostras reduzidas de 16384 para 2000 bytes (×FBC_ESCALA);
# contexto de 8 bits e limite de 55% mantidos. O contexto é atualizado de
# forma incremental (janela deslizante) para não pagar um laço interno por bit.
AtaquePreditorDeBits() {
    ATQ_NOME="Previsibilidade de bits (preditor por contexto)"

    local tamanho=$(( 2000 * FBC_ESCALA ))
    local k=8
    local limite="0.55"

    local -a key iv ks bits
    string_to_bytes key "$(alvo_chave_de_teste)"
    util_random_bytes iv 16
    alvo_gerar_keystream_bruto ks "${key[*]}" "${iv[*]}" "101 110 99" "$tamanho"
    if [ "${#ks[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerarKeystreamBruto."
        return 0
    fi

    # Converte os bytes em um array de bits (MSB primeiro), como no PHP.
    bits=()
    local byte b
    for byte in "${ks[@]}"; do
        for (( b = 7; b >= 0; b-- )); do
            bits+=( $(( (byte >> b) & 1 )) )
        done
    done

    local n=${#bits[@]}
    local total=$(( 1 << k ))
    local mask=$(( total - 1 ))
    local metade=$(( n / 2 ))

    local -a uns cont
    local i j ctx pred acertos testes
    for (( i = 0; i < total; i++ )); do
        uns[i]=0
        cont[i]=0
    done

    # Inicializa o contexto com os k primeiros bits.
    ctx=0
    for (( j = 0; j < k; j++ )); do
        ctx=$(( (ctx << 1) | bits[j] ))
    done

    acertos=0
    testes=0
    for (( i = k; i < n; i++ )); do
        # ctx = bits[i-k .. i-1]
        if [ "$i" -lt "$metade" ]; then
            uns[ctx]=$(( uns[ctx] + bits[i] ))
            cont[ctx]=$(( cont[ctx] + 1 ))
        else
            if [ "${cont[ctx]}" -ne 0 ]; then
                if [ $(( uns[ctx] * 2 )) -gt "${cont[ctx]}" ]; then
                    pred=1
                else
                    pred=0
                fi
                if [ "$pred" -eq "${bits[i]}" ]; then
                    acertos=$(( acertos + 1 ))
                fi
                testes=$(( testes + 1 ))
            fi
        fi
        # Avança a janela deslizante para a próxima posição.
        ctx=$(( ((ctx << 1) | bits[i]) & mask ))
    done

    local taxa taxa_pct
    taxa=$(util_div "$acertos" "$testes" 6)
    taxa_pct=$(util_pct "$acertos" "$testes" 2)

    if util_maior "$taxa" "$limite"; then
        res_vulneravel "taxa de acerto=${taxa_pct}% com contexto de ${k} bits (esperado ~50%, limite=55%) sobre ${testes} testes" "alta"
    else
        res_resistiu "taxa de acerto=${taxa_pct}% com contexto de ${k} bits (esperado ~50%, limite=55%) sobre ${testes} testes"
    fi
    return 0
}
