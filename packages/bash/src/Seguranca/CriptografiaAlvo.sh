# Liga a suíte de ataques à implementação real (src/Core/Criptografia.sh).
#
# Requer que Criptografia.sh já tenha sido sourceado. Em bash não há classes:
# o "alvo" é um conjunto de funções + a global ALVO_CHAVE.

ALVO_CHAVE="${ALVO_CHAVE:-pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf}"

alvo_init() {
    ALVO_CHAVE="${1:-$ALVO_CHAVE}"
    export FBC_KEY="$ALVO_CHAVE"
}

alvo_encrypt() {
    cripto_encrypt "$1"
}

alvo_decrypt() {
    cripto_decrypt "$1"
}

alvo_prefixo() {
    echo "FBC"
}

alvo_chave_de_teste() {
    echo "$ALVO_CHAVE"
}

alvo_tamanho_iv() {
    echo 16
}

# alvo_decompor <nome_integridade> <nome_ciphertext> <nome_iv> <bytes_decimais>
alvo_decompor() {
    local -n _integ=$1 _cipher=$2 _iv=$3
    local -a buf=($4)
    local total=${#buf[@]}
    local tam_iv=16
    _integ=("${buf[@]:0:32}")
    _cipher=("${buf[@]:32:$(( total - 32 - tam_iv ))}")
    _iv=("${buf[@]:$(( total - tam_iv ))}")
}

# alvo_recompor <nome_saida> <integridade> <ciphertext> <iv>
alvo_recompor() {
    local -n _out=$1
    local -a integ=($2) ct=($3) iv=($4)
    _out=("${integ[@]}" "${ct[@]}" "${iv[@]}")
}

# alvo_gerar_keystream_bruto <nome_saida> <key> <iv> <proposito> <tamanho>
alvo_gerar_keystream_bruto() {
    local -n _out=$1
    gerar_keystream _out "$2" "$3" "$4" "$5"
}

# alvo_checksum_bruto <nome_saida> <dados> <key>
alvo_checksum_bruto() {
    local -n _out=$1
    checksum _out "$2" "$3"
}

# Codifica uma string de bytes decimais como base64url (sem padding).
alvo_base64url_encode() {
    local -a bytes=($1)
    bytes_to_stdout "${bytes[@]}" | base64url_encode_stdin
}

# Decodifica base64url para o array (nameref) de bytes decimais.
alvo_base64url_decode() {
    local -n _out=$1
    base64url_decode_to_array _out "$2"
}
