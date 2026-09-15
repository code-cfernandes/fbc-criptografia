# Um mesmo token não deveria ter múltiplas representações textuais válidas.
# Se o decoder de base64url ignora caracteres fora do alfabeto (comportamento
# padrão do base64_decode não-estrito) ou aceita o alfabeto padrão (+/) no
# lugar do URL-safe (-_), então strings diferentes decodificam para o MESMO
# token. Isso é "token smuggling": sistemas que comparam/usam a string do
# token de formas diferentes (cache, WAF, deduplicação/replay) discordam
# sobre o que ele significa.
AtaqueCanonicalizacaoToken() {
    ATQ_NOME="Canonicalização do token (base64 não-canônico)"

    local texto="MENSAGEM_DE_TESTE_DE_CANONICALIZACAO"
    local token
    if ! token=$(alvo_encrypt "$texto" 2>/dev/null); then
        res_erro "Falha ao cifrar mensagem de teste."
        return 0
    fi

    local prefixo
    prefixo=$(alvo_prefixo)
    local plen=${#prefixo}
    local corpo="${token:$plen}"
    local meio=$(( ${#corpo} / 2 ))

    local -a nomes=()
    local -a vals=()
    local p
    for p in 0 "$meio" $(( ${#corpo} - 1 )); do
        nomes+=("espaço na posição $p")
        vals+=("$prefixo${corpo:0:p} ${corpo:p}")
        nomes+=("newline na posição $p")
        vals+=("$prefixo${corpo:0:p}"$'\n'"${corpo:p}")
        nomes+=("tab na posição $p")
        vals+=("$prefixo${corpo:0:p}"$'\t'"${corpo:p}")
    done

    local padrao="${corpo//-/+}"
    padrao="${padrao//_//}"
    nomes+=("alfabeto padrão (+/)")
    vals+=("$prefixo$padrao")
    nomes+=('padding "=" extra')
    vals+=("$prefixo$corpo=")
    nomes+=("caractere inválido no meio")
    vals+=("$prefixo${corpo:0:meio}!${corpo:meio}")

    local -a aceitas=()
    local i
    for (( i = 0; i < ${#vals[@]}; i++ )); do
        local v=${vals[i]}
        if [ "$v" = "$token" ]; then
            continue
        fi
        local saida
        if saida=$(alvo_decrypt "$v" 2>/dev/null); then
            if [ "$saida" = "$texto" ]; then
                aceitas+=("${nomes[i]}")
            fi
        fi
    done

    if [ ${#aceitas[@]} -gt 0 ]; then
        local lista=""
        local a
        for a in "${aceitas[@]}"; do
            if [ -n "$lista" ]; then
                lista+="; "
            fi
            lista+="$a"
        done
        res_vulneravel "${#aceitas[@]} variante(s) textualmente diferente(s) decifram para o mesmo texto: $lista" "media"
    else
        res_resistiu "Todas as ${#vals[@]} variantes não-canônicas foram rejeitadas" "info"
    fi
    return 0
}
