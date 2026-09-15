# As primeiras versões dessa cifra tinham um header fixo (43 bytes idênticos
# sempre) ou um marcador constante (o '$' na posição 64). Esse ataque gera
# vários tokens de textos diferentes e procura qualquer posição de byte que
# NUNCA muda - isso é uma âncora que um atacante pode usar pra recuperar a
# chave (como fizemos na primeira rodada dessa conversa).
AtaqueBytesFixos() {
    ATQ_NOME="Bytes fixos entre tokens"

    # Reduzido de 30 para ~10 amostras (bash é ordens de magnitude mais lento).
    local amostras=$(( 10 * FBC_ESCALA ))

    local -a decodificados=()
    local i
    for (( i = 0; i < amostras; i++ )); do
        local texto="TEXTO_VARIADO_$i"
        local rep=$(( i % 10 ))
        if [ "$rep" -gt 0 ]; then
            local oct ch k
            printf -v oct '%03o' $(( 65 + (i % 26) ))
            printf -v ch '%b' "\\$oct"
            for (( k = 0; k < rep; k++ )); do
                texto+="$ch"
            done
        fi

        local token
        if ! token=$(alvo_encrypt "$texto" 2>/dev/null); then
            continue
        fi
        local -a dec=()
        if ! alvo_base64url_decode dec "${token:3}"; then
            continue
        fi
        decodificados+=("${dec[*]}")
    done

    local total=${#decodificados[@]}
    if [ "$total" -eq 0 ]; then
        res_erro "Nenhum token pôde ser gerado/decodificado."
        return 0
    fi

    local min=-1
    for (( i = 0; i < total; i++ )); do
        local -a tmp=(${decodificados[i]})
        if [ "$min" -lt 0 ] || [ "${#tmp[@]}" -lt "$min" ]; then
            min=${#tmp[@]}
        fi
    done

    local -a posicoes=()
    local pos
    for (( pos = 0; pos < min; pos++ )); do
        local -a base=(${decodificados[0]})
        local primeiro=${base[pos]}
        local todos=1
        local j
        for (( j = 1; j < total; j++ )); do
            local -a tmp=(${decodificados[j]})
            if [ "${tmp[pos]}" != "$primeiro" ]; then
                todos=0
                break
            fi
        done
        if [ "$todos" -eq 1 ]; then
            posicoes+=("$pos")
        fi
    done

    if [ ${#posicoes[@]} -gt 0 ]; then
        local lista=""
        local limite=${#posicoes[@]}
        if [ "$limite" -gt 10 ]; then
            limite=10
        fi
        for (( i = 0; i < limite; i++ )); do
            if [ -n "$lista" ]; then
                lista+=", "
            fi
            lista+="${posicoes[i]}"
        done
        res_vulneravel "${#posicoes[@]} posição(ões) de byte fixas em $total tokens: $lista" "alta"
    else
        res_resistiu "0 de $min posições fixas em $total tokens" "info"
    fi
    return 0
}
