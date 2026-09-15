# Ataque ao MAC: tenta truncar o campo de integridade, zerá-lo e forçar
# (força bruta de 1 byte) valores para ver se algum token adulterado é aceito.
# Com um MAC de 32 bytes, nenhuma tentativa deveria passar.
AtaqueMac() {
    ATQ_NOME="Força bruta e truncamento do MAC"

    local mensagem="mensagem para o ataque de MAC"
    local token
    if ! token=$(alvo_encrypt "$mensagem" 2>/dev/null); then
        res_erro "Falha ao cifrar mensagem de teste."
        return 0
    fi

    local prefixo
    prefixo=$(alvo_prefixo)
    local -a decoded=()
    if ! alvo_base64url_decode decoded "${token:${#prefixo}}"; then
        res_erro "Falha ao decodificar token."
        return 0
    fi

    local -a integ=() ct=() iv=()
    alvo_decompor integ ct iv "${decoded[*]}"

    local -a aceitos=()
    local -a payload=()
    local t saida

    # 1) integridade zerada
    local -a zeros=()
    local i
    for (( i = 0; i < ${#integ[@]}; i++ )); do
        zeros+=(0)
    done
    alvo_recompor payload "${zeros[*]}" "${ct[*]}" "${iv[*]}"
    t="${prefixo}$(alvo_base64url_encode "${payload[*]}")"
    if saida=$(alvo_decrypt "$t" 2>/dev/null); then
        aceitos+=("integridade zerada")
    fi

    # 2) integridade truncada pela metade
    local -a trunc=("${integ[@]:0:16}")
    alvo_recompor payload "${trunc[*]}" "${ct[*]}" "${iv[*]}"
    t="${prefixo}$(alvo_base64url_encode "${payload[*]}")"
    if saida=$(alvo_decrypt "$t" 2>/dev/null); then
        aceitos+=("integridade truncada (16 bytes)")
    fi

    # 3) força bruta de 1 byte do MAC (255 variantes; pula o valor original,
    # que reconstruiria o próprio token válido e não é uma forja)
    local original=${integ[0]}
    local v
    for (( v = 0; v < 256; v++ )); do
        if [ "$v" -eq "$original" ]; then
            continue
        fi
        local -a tent=("${integ[@]}")
        tent[0]=$v
        alvo_recompor payload "${tent[*]}" "${ct[*]}" "${iv[*]}"
        t="${prefixo}$(alvo_base64url_encode "${payload[*]}")"
        if saida=$(alvo_decrypt "$t" 2>/dev/null); then
            aceitos+=("byte 0 do MAC = $v")
        fi
    done

    if [ "${#aceitos[@]}" -gt 0 ]; then
        local lista
        lista=$(printf '%s; ' "${aceitos[@]:0:5}")
        lista=${lista%; }
        res_vulneravel "${#aceitos[@]} variante(s) de MAC aceitas: $lista" "critica"
    else
        res_resistiu "Nenhuma das 257 variantes (zerada, truncada, 255 bytes forçados) foi aceita" "info"
    fi
    return 0
}
