# O token é integridade[32] . ciphertext[n] . iv[16]. Se o parser for
# ambíguo, um atacante pode reordenar/deslocar os campos e construir um
# token que sistemas diferentes interpretam de formas diferentes. Todos os
# rearranjos devem ser rejeitados pela integridade.

AtaqueConfusaoCampos() {
    ATQ_NOME="Confusão de campos do token (reordenação/deslocamento)"

    local texto='MENSAGEM_PARA_TESTE_DE_CAMPOS'
    local token prefixo
    token=$(alvo_encrypt "$texto")
    prefixo=$(alvo_prefixo)

    local -a dec
    alvo_base64url_decode dec "${token:${#prefixo}}"

    local -a integridade ciphertext iv
    alvo_decompor integridade ciphertext iv "${dec[*]}"

    # prepara os pedaços usados nos rearranjos
    local -a integ_cortada=("${integridade[@]:1}")
    local -a iv_rev=()
    local i
    for (( i = ${#iv[@]} - 1; i >= 0; i-- )); do
        iv_rev+=("${iv[i]}")
    done
    local -a ct_sem_ultimo=("${ciphertext[@]:0:${#ciphertext[@]} - 1}")
    local ultimo_byte="${ciphertext[${#ciphertext[@]} - 1]}"

    local -a nomes=() variantes=()
    nomes+=("iv no início"); variantes+=("${iv[*]} ${integridade[*]} ${ciphertext[*]}")
    nomes+=("ciphertext antes da integridade"); variantes+=("${ciphertext[*]} ${integridade[*]} ${iv[*]}")
    nomes+=("iv duplicado no fim"); variantes+=("${integridade[*]} ${ciphertext[*]} ${iv[*]} ${iv[*]}")
    nomes+=("integridade encurtada"); variantes+=("${integ_cortada[*]} ${ciphertext[*]} ${iv[*]}")
    nomes+=("byte extra no início"); variantes+=("88 ${integridade[*]} ${ciphertext[*]} ${iv[*]}")
    nomes+=("byte extra entre integridade e ciphertext"); variantes+=("${integridade[*]} 88 ${ciphertext[*]} ${iv[*]}")
    nomes+=("byte extra antes do iv"); variantes+=("${integridade[*]} ${ciphertext[*]} 88 ${iv[*]}")
    nomes+=("iv rotacionado"); variantes+=("${integridade[*]} ${ciphertext[*]} ${iv_rev[*]}")
    nomes+=("iv e último byte do ciphertext trocados"); variantes+=("${integridade[*]} ${ct_sem_ultimo[*]} ${iv[*]} $ultimo_byte")

    local aceitas=0 idx
    for idx in "${!variantes[@]}"; do
        local token_variante
        token_variante="${prefixo}$(alvo_base64url_encode "${variantes[idx]}")"
        local r
        if r=$(alvo_decrypt "$token_variante" 2>/dev/null); then
            aceitas=$(( aceitas + 1 ))
        fi
    done

    if [ "$aceitas" -gt 0 ]; then
        res_vulneravel "$aceitas rearranjo(s) de campo foram aceitos" critica
    else
        res_resistiu "Todos os ${#variantes[@]} rearranjos de campo foram rejeitados"
    fi
    return 0
}
