# O ataque mais importante da suíte: se um bit flipado em QUALQUER campo do
# token (ciphertext, iv, ou o campo de integridade) ainda decifra "com
# sucesso", a cifra não está autenticando o conteúdo - é a falha que
# encontramos e corrigimos várias vezes ao longo dessa conversa.
AtaqueAdulteracao() {
    ATQ_NOME="Adulteração de bits (integridade)"

    # Reduzido de 500 para ~30 amostras (bash é ordens de magnitude mais lento).
    local tentativas=$(( 30 * FBC_ESCALA ))
    local aceitos=0
    local t

    for (( t = 0; t < tentativas; t++ )); do
        local texto="MSG_$t"
        local n_x
        n_x=$(util_random_int 0 50)
        local k
        for (( k = 0; k < n_x; k++ )); do
            texto+="X"
        done

        local token
        if ! token=$(alvo_encrypt "$texto" 2>/dev/null); then
            continue
        fi

        local -a decoded=()
        if ! alvo_base64url_decode decoded "${token:3}"; then
            continue
        fi

        local -a integ=()
        local -a ct=()
        local -a iv=()
        alvo_decompor integ ct iv "${decoded[*]}"

        local campo nome_campo tam pos bit
        campo=$(util_random_int 0 2)
        case "$campo" in
            0)
                nome_campo="integridade"
                tam=${#integ[@]}
                if [ "$tam" -gt 0 ]; then
                    pos=$(util_random_int 0 $(( tam - 1 )))
                    bit=$(( 1 << $(util_random_int 0 7) ))
                    integ[pos]=$(( integ[pos] ^ bit ))
                fi
                ;;
            1)
                nome_campo="ciphertext"
                tam=${#ct[@]}
                if [ "$tam" -gt 0 ]; then
                    pos=$(util_random_int 0 $(( tam - 1 )))
                    bit=$(( 1 << $(util_random_int 0 7) ))
                    ct[pos]=$(( ct[pos] ^ bit ))
                fi
                ;;
            2)
                nome_campo="iv"
                tam=${#iv[@]}
                if [ "$tam" -gt 0 ]; then
                    pos=$(util_random_int 0 $(( tam - 1 )))
                    bit=$(( 1 << $(util_random_int 0 7) ))
                    iv[pos]=$(( iv[pos] ^ bit ))
                fi
                ;;
        esac

        if [ "$tam" -eq 0 ]; then
            continue
        fi

        local -a payload=()
        alvo_recompor payload "${integ[*]}" "${ct[*]}" "${iv[*]}"
        local token_adulterado="$(alvo_prefixo)$(alvo_base64url_encode "${payload[*]}")"

        local saida
        if saida=$(alvo_decrypt "$token_adulterado" 2>/dev/null); then
            aceitos=$(( aceitos + 1 ))
        fi
    done

    if [ "$aceitos" -gt 0 ]; then
        res_vulneravel "$aceitos de $tentativas tokens adulterados foram ACEITOS" "critica"
    else
        res_resistiu "Todas as $tentativas adulterações foram rejeitadas" "info"
    fi
    return 0
}
