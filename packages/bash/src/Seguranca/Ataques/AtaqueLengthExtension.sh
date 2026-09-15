# Length extension / truncamento: a estrutura do token é
# integridade[32] . ciphertext[n] . iv[16], e o MAC cobre iv+ciphertext.
# Truncar, estender ou deslocar bytes não pode produzir um token aceito.
AtaqueLengthExtension() {
    ATQ_NOME="Length extension / truncamento de token"

    local mensagem="texto para o ataque de length extension"
    local token
    if ! token=$(alvo_encrypt "$mensagem" 2>/dev/null); then
        res_erro "Falha ao cifrar mensagem de teste."
        return 0
    fi

    local prefixo
    prefixo=$(alvo_prefixo)
    local corpo="${token:${#prefixo}}"
    local meio=$(( ${#corpo} / 2 ))

    local -a nomes=()
    local -a vals=()

    nomes+=("append A")
    vals+=("${prefixo}${corpo}A")
    nomes+=("append =")
    vals+=("${prefixo}${corpo}=")
    nomes+=("truncar 1 char")
    vals+=("${prefixo}${corpo:0:$((${#corpo} - 1))}")
    nomes+=("truncar 2 chars")
    vals+=("${prefixo}${corpo:0:$((${#corpo} - 2))}")
    nomes+=("inserir ! no meio")
    vals+=("${prefixo}${corpo:0:meio}!${corpo:meio}")
    nomes+=("prefixo extra")
    vals+=("${prefixo}A${corpo}")

    # variantes que mexem nos campos decodificados
    local -a decoded=()
    if alvo_base64url_decode decoded "$corpo"; then
        local -a integ=() ct=() iv=()
        alvo_decompor integ ct iv "${decoded[*]}"
        local -a payload=()

        local -a ct_maior=("${ct[@]}" 65)
        alvo_recompor payload "${integ[*]}" "${ct_maior[*]}" "${iv[*]}"
        nomes+=("ciphertext +1 byte")
        vals+=("${prefixo}$(alvo_base64url_encode "${payload[*]}")")

        local -a ct_menor=("${ct[@]:0:$((${#ct[@]} - 1))}")
        alvo_recompor payload "${integ[*]}" "${ct_menor[*]}" "${iv[*]}"
        nomes+=("ciphertext -1 byte")
        vals+=("${prefixo}$(alvo_base64url_encode "${payload[*]}")")

        local -a iv_maior=("${iv[@]}" 66)
        alvo_recompor payload "${integ[*]}" "${ct[*]}" "${iv_maior[*]}"
        nomes+=("iv +1 byte")
        vals+=("${prefixo}$(alvo_base64url_encode "${payload[*]}")")
    fi

    local -a aceitas=()
    local i
    for (( i = 0; i < ${#vals[@]}; i++ )); do
        if [ "${vals[i]}" = "$token" ]; then
            continue
        fi
        local saida
        if saida=$(alvo_decrypt "${vals[i]}" 2>/dev/null); then
            aceitas+=("${nomes[i]}")
        fi
    done

    if [ "${#aceitas[@]}" -gt 0 ]; then
        local lista
        lista=$(printf '%s; ' "${aceitas[@]}")
        lista=${lista%; }
        res_vulneravel "${#aceitas[@]} variante(s) aceita(s): $lista" "critica"
    else
        res_resistiu "Todas as ${#vals[@]} variantes de truncamento/extensão foram rejeitadas" "info"
    fi
    return 0
}
