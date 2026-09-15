# AtaqueDistribuicaoBytes
#
# Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
# 0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
# de byte saem com mais frequência que outros - sinal de fraqueza estatística
# na função de mistura.

AtaqueDistribuicaoBytes() {
    ATQ_NOME="Distribuição de bytes (qui-quadrado)"

    local tamanhoBloco=32
    # PHP usava 500 blocos (16000 bytes); reduzido para ~2000 bytes.
    local amostrasDeBlocos=$(( 63 * FBC_ESCALA ))

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a contagem=()
    local i j
    for (( i = 0; i < 256; i++ )); do
        contagem[i]=0
    done

    local -a iv ks
    local total=0
    for (( i = 0; i < amostrasDeBlocos; i++ )); do
        util_random_bytes iv "$(alvo_tamanho_iv)"
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanhoBloco"
        for (( j = 0; j < ${#ks[@]}; j++ )); do
            contagem[${ks[j]}]=$(( contagem[${ks[j]}] + 1 ))
            total=$(( total + 1 ))
        done
    done

    local qui2
    qui2=$(awk -v total="$total" -v lista="$(printf '%s ' "${contagem[@]}")" 'BEGIN {
        split(lista, c, " ");
        esperado = total / 256;
        q = 0;
        for (i in c) {
            if (c[i] == "") continue;
            d = c[i] - esperado;
            q += d * d / esperado;
        }
        printf "%.1f", q;
    }')

    # Com 255 graus de liberdade, valores acima de ~330 já são
    # estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
    local vulneravel=0
    if util_maior "$qui2" 330; then
        vulneravel=1
    fi

    local detalhes="qui-quadrado=${qui2} sobre ${total} bytes (255 graus de liberdade; >330 é suspeito)"
    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "media"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
