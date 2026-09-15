# Linearidade e diferenciais do checksum.
#
# Procura linearidade no checksum, que seria fatal para um MAC:
#  1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
#  2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para
#     cada a; se repetir muito, existe um diferencial de alta probabilidade
#     que ajuda a forjar MACs.
#
# Adaptação bash: relações reduzidas de 5000 para 200 e diferenciais de 500
# para 50 por delta (ambos × FBC_ESCALA). Checksum em bash é rápido, então o
# custo dominante é gerar os arrays aleatórios.

AtaqueLinearidadeChecksum() {
    ATQ_NOME="Linearidade e diferenciais do checksum"

    if ! declare -F alvo_checksum_bruto >/dev/null; then
        res_skip "Alvo não expõe checksum_bruto."
        return 0
    fi

    local amostras_linearidade=$(( 200 * FBC_ESCALA ))
    local amostras_diferencial=$(( 50 * FBC_ESCALA ))
    local tamanho_entrada=32

    local -a chave_mac=()
    local i
    for (( i = 0; i < 32; i++ )); do
        chave_mac+=(77)
    done

    local -a primeiro=() teste_dados=()
    string_to_bytes teste_dados "teste"
    alvo_checksum_bruto primeiro "${teste_dados[*]}" "${chave_mac[*]}"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe checksum_bruto."
        return 0
    fi

    local -a a=() b=() ab=() ca=() cb=() cr=() lhs=() ad=() delta=() dif=()
    local k

    local relacoes_lineares=0
    for (( i = 0; i < amostras_linearidade; i++ )); do
        util_random_bytes a "$tamanho_entrada"
        util_random_bytes b "$tamanho_entrada"

        alvo_checksum_bruto ca "${a[*]}" "${chave_mac[*]}"
        alvo_checksum_bruto cb "${b[*]}" "${chave_mac[*]}"
        lhs=()
        for (( k = 0; k < ${#ca[@]}; k++ )); do
            lhs+=($(( ca[k] ^ cb[k] )))
        done

        ab=()
        for (( k = 0; k < tamanho_entrada; k++ )); do
            ab+=($(( a[k] ^ b[k] )))
        done
        alvo_checksum_bruto cr "${ab[*]}" "${chave_mac[*]}"

        if [ "${lhs[*]}" = "${cr[*]}" ]; then
            relacoes_lineares=$(( relacoes_lineares + 1 ))
        fi
    done

    local max_repeticoes=0
    local d i2 cnt
    for (( d = 0; d < 5; d++ )); do
        util_random_bytes delta "$tamanho_entrada"
        declare -A vistos=()
        for (( i2 = 0; i2 < amostras_diferencial; i2++ )); do
            util_random_bytes a "$tamanho_entrada"

            ad=()
            for (( k = 0; k < tamanho_entrada; k++ )); do
                ad+=($(( a[k] ^ delta[k] )))
            done
            alvo_checksum_bruto ca "${ad[*]}" "${chave_mac[*]}"
            alvo_checksum_bruto cb "${a[*]}" "${chave_mac[*]}"

            dif=()
            for (( k = 0; k < ${#ca[@]}; k++ )); do
                dif+=($(( ca[k] ^ cb[k] )))
            done
            vistos["${dif[*]}"]=$(( ${vistos["${dif[*]}"]:-0} + 1 ))
        done

        for cnt in "${vistos[@]}"; do
            if [ "$cnt" -gt "$max_repeticoes" ]; then
                max_repeticoes=$cnt
            fi
        done
    done

    local vulneravel=0
    if [ "$relacoes_lineares" -gt 0 ] || [ "$max_repeticoes" -gt 1 ]; then
        vulneravel=1
    fi

    local detalhe
    detalhe=$(printf '%d/%d relações lineares; maior repetição de diferencial=%d (esperado 1)' \
        "$relacoes_lineares" "$amostras_linearidade" "$max_repeticoes")

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhe" "critica"
    else
        res_resistiu "$detalhe" "info"
    fi
    return 0
}
