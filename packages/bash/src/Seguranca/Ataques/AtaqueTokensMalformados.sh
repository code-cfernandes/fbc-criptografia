# Robustez do parser de tokens: qualquer entrada que não seja um token
# íntegro e bem formado DEVE ser rejeitada com exceção. Um decrypt() que
# devolve lixo em vez de lançar (ou que aceita truncamentos/bytes extras)
# é uma porta pra bugs de validação e "token smuggling".
AtaqueTokensMalformados() {
    ATQ_NOME="Tokens malformados (fuzzing de entrada)"

    local token prefixo corpo
    token="$(alvo_encrypt 'MENSAGEM_VALIDA_PARA_TESTE')"
    prefixo="$(alvo_prefixo)"
    corpo="${token:${#prefixo}}"

    local -a nomes tokens
    nomes=("vazio" "só prefixo" "prefixo errado" "base64 inválido" "bytes extras no fim" "bytes extras no início")
    tokens=("" "$prefixo" "XXX${corpo}" "${prefixo}!!!@@@###" "${token}AAAA" "AAAA${token}")

    local len
    for (( len = 1; len < ${#token}; len++ )); do
        nomes+=("truncado em $len")
        tokens+=("${token:0:len}")
    done

    local i
    local -a rnd
    for (( i = 0; i < 20; i++ )); do
        util_random_bytes rnd 16
        nomes+=("lixo aleatório $i")
        tokens+=("${prefixo}$(printf '%02x' "${rnd[@]}")")
    done

    local total=${#tokens[@]}
    local aceitos=0 saida
    for (( i = 0; i < total; i++ )); do
        if saida=$(alvo_decrypt "${tokens[i]}" 2>/dev/null); then
            aceitos=$(( aceitos + 1 ))
        fi
    done

    if [ "$aceitos" -gt 0 ]; then
        res_vulneravel "${aceitos} entrada(s) malformada(s) foram ACEITAS em vez de rejeitadas" "critica"
    else
        res_resistiu "Todas as ${total} entradas malformadas foram rejeitadas"
    fi
    return 0
}
