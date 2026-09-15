# Garante que um token só decifra com a chave correta: com qualquer outra
# chave de 32 bytes, decrypt() tem que falhar. Verifica também que a chave
# errada não "quase funciona" (ex: aceitar às vezes por MAC fraco).
#
# Cuidado: o alvo escreve a chave no ambiente do processo (FBC_KEY); a chave
# original é restaurada no final pra não afetar os outros ataques.

AtaqueChaveErrada() {
    ATQ_NOME="Rejeição de chave incorreta"

    local tentativas=$(( 10 * FBC_ESCALA ))
    local chave_original
    chave_original=$(alvo_chave_de_teste)

    local -a tokens=()
    local i token
    for (( i = 0; i < tentativas; i++ )); do
        tokens+=("$(alvo_encrypt "MENSAGEM_SECRETA_$i")")
    done

    local aceitos=0 saida chave_errada
    for (( i = 0; i < tentativas; i++ )); do
        token=${tokens[i]}
        # chave errada de 32 bytes (equivalente a bin2hex(random_bytes(16)))
        local -a kb=()
        util_random_bytes kb 16
        chave_errada=""
        local x hex
        for x in "${kb[@]}"; do
            printf -v hex '%02x' "$x"
            chave_errada+="$hex"
        done
        export FBC_KEY="$chave_errada"
        if saida=$(alvo_decrypt "$token" 2>/dev/null); then
            aceitos=$(( aceitos + 1 ))
        fi
    done
    # finally: restaura a chave original
    export FBC_KEY="$chave_original"

    if [ "$aceitos" -gt 0 ]; then
        res_vulneravel "$aceitos de $tentativas tokens foram aceitos com a chave errada" critica
    else
        res_resistiu "Nenhum dos $tentativas tokens foi aceito com chave incorreta"
    fi
    return 0
}
