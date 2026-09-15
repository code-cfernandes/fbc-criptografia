# A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
# reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão).
# Esse ataque usa o gerador de keystream de baixo nível pra SIMULAR o que
# aconteceria SE o IV fosse reusado (por um bug externo, uma falha do
# gerador aleatório do sistema, etc.) - e prova matematicamente o quanto
# vaza nesse cenário catastrófico.
#
# Isso não é um "bug" da implementação (é uma propriedade universal de
# qualquer cifra de fluxo com combinador XOR/soma) - é uma demonstração
# quantificada de por que o AtaqueColisaoIV é o teste mais crítico da
# suíte: a segurança inteira depende do IV nunca repetir.
AtaqueReusoIV() {
    ATQ_NOME="Reuso forçado de IV (two-time pad)"

    local chave
    chave="$(alvo_chave_de_teste)"

    local -a key iv primeiro_ks
    string_to_bytes key "$chave"
    util_random_bytes iv 16

    alvo_gerar_keystream_bruto primeiro_ks "${key[*]}" "${iv[*]}" "101 110 99" 16
    if [ "${#primeiro_ks[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerarKeystreamBruto."
        return 0
    fi

    local plaintext1='TRANSFERIR_1000'
    local plaintext2='CANCELAR_TUDO!!'
    local tamanho=${#plaintext1}
    [ "${#plaintext2}" -gt "$tamanho" ] && tamanho=${#plaintext2}

    local -a ks b1 b2 c1 c2 xc xp
    alvo_gerar_keystream_bruto ks "${key[*]}" "${iv[*]}" "101 110 99" "$tamanho"
    string_to_bytes b1 "$plaintext1"
    string_to_bytes b2 "$plaintext2"

    local i
    c1=()
    c2=()
    for (( i = 0; i < tamanho; i++ )); do
        c1+=( $(( b1[i] ^ ks[i] )) )
        c2+=( $(( b2[i] ^ ks[i] )) )
    done

    # O atacante NUNCA precisou saber a key nem o keystream - só observou os
    # dois ciphertexts (que vazariam publicamente se o IV fosse reusado) e os
    # combinou entre si.
    xc=()
    xp=()
    for (( i = 0; i < tamanho; i++ )); do
        xc+=( $(( c1[i] ^ c2[i] )) )
        xp+=( $(( b1[i] ^ b2[i] )) )
    done

    if [ "${xc[*]}" = "${xp[*]}" ]; then
        res_demonstracao "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)."
    else
        res_vulneravel "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)" "alta"
    fi
    return 0
}
