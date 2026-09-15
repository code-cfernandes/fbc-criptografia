# Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico -
# chamar a função duas vezes com a mesma entrada tem que dar o mesmo
# resultado, sempre. Se não der, alguma fonte de aleatoriedade (relógio,
# random_bytes, uniqid, etc.) vazou pra dentro de uma função que deveria
# ser pura - isso quebraria o decrypt() em produção de forma intermitente
# e seria um pesadelo de debugar.
#
# De brinde, esse ataque imprime o "vetor de referência" (Known Answer
# Vector) pra esse par key/iv - guarde esse valor: se ele mudar entre
# versões do código sem você ter mexido de propósito na lógica de mistura,
# é sinal de uma regressão acidental.
AtaqueVetorDeterministico() {
    ATQ_NOME="Determinismo (vetor de referência key/iv fixos)"

    local chave_teste
    chave_teste="$(alvo_chave_de_teste)"
    local tamChave=${#chave_teste}
    local tamIv
    tamIv=$(alvo_tamanho_iv)

    local -a keyFixa ivFixo ks1 ks2 ks3
    string_to_bytes keyFixa "$(printf 'K%.0s' $(seq 1 "$tamChave"))"
    ivFixo=()
    local i
    for (( i = 0; i < tamIv; i++ )); do
        ivFixo+=(0)
    done

    alvo_gerar_keystream_bruto ks1 "${keyFixa[*]}" "${ivFixo[*]}" "101 110 99" 32
    if [ "${#ks1[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerarKeystreamBruto."
        return 0
    fi
    alvo_gerar_keystream_bruto ks2 "${keyFixa[*]}" "${ivFixo[*]}" "101 110 99" 32
    alvo_gerar_keystream_bruto ks3 "${keyFixa[*]}" "${ivFixo[*]}" "101 110 99" 32

    if [ "${ks1[*]}" = "${ks2[*]}" ] && [ "${ks2[*]}" = "${ks3[*]}" ]; then
        res_resistiu "Determinístico em 3 chamadas. Vetor de referência (key=${tamChave}x\"K\", iv=zeros, prop=enc, 32 bytes): $(printf '%02x' "${ks1[@]}")"
    else
        res_vulneravel "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: $(printf '%02x' "${ks1[@]}") / $(printf '%02x' "${ks2[@]}") / $(printf '%02x' "${ks3[@]}")" "critica"
    fi
    return 0
}
