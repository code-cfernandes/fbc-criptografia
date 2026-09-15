# Mensagens longas (multi-bloco).
#
# Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
# sincronização de bloco, repetição de keystream em blocos distantes ou
# perda de bytes aparecem só em mensagens longas - os testes de ida-e-volta
# curtos não pegam. Também confirma que o mesmo texto com IVs diferentes
# gera tokens diferentes.
#
# Adaptação bash: tamanhos reduzidos de [1000, 10000, 100000] para
# [100, 500, 1000]. O texto binário é montado com `printf -v` e a saída do
# decrypt é lida com `od` (enxerga NUL/newline). Bytes 0x00 são remapeados
# pra 0x01 porque bash não guarda NUL em string.

AtaqueMensagemLonga() {
    ATQ_NOME="Mensagens longas (multi-bloco)"

    local -a tamanhos=(100 500 1000)
    local -a falhas=()
    local t k v val
    local esc oct texto token
    local -a originais=() decifrados=()

    for t in "${tamanhos[@]}"; do
        util_random_bytes originais "$t"
        esc=""
        for (( k = 0; k < t; k++ )); do
            v=${originais[k]}
            if [ "$v" -eq 0 ]; then
                v=1
                originais[k]=1
            fi
            printf -v oct '%03o' "$v"
            esc+="\\$oct"
        done
        printf -v texto '%b' "$esc"

        if token=$(alvo_encrypt "$texto" 2>/dev/null); then
            decifrados=()
            while read -r val; do
                decifrados+=("$val")
            done < <(alvo_decrypt "$token" 2>/dev/null | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
            if [ "${#decifrados[@]}" -gt 0 ]; then
                decifrados=("${decifrados[@]:0:${#decifrados[@]}-1}")
            fi
            if [ "${decifrados[*]}" != "${originais[*]}" ]; then
                falhas+=("$t bytes (conteúdo diferente)")
            fi
        else
            falhas+=("$t bytes (erro: encrypt falhou)")
        fi
    done

    local texto_a=""
    for (( k = 0; k < 1000; k++ )); do
        texto_a+="A"
    done
    local t1 t2
    t1=$(alvo_encrypt "$texto_a" 2>/dev/null)
    t2=$(alvo_encrypt "$texto_a" 2>/dev/null)
    if [ "$t1" = "$t2" ]; then
        falhas+=("tokens idênticos para o mesmo texto (IV não varia)")
    fi

    if [ "${#falhas[@]}" -gt 0 ]; then
        local detalhe
        detalhe=$(printf '%s; ' "${falhas[@]}")
        detalhe=${detalhe%; }
        res_vulneravel "Falha em: $detalhe" "critica"
        return 0
    fi

    res_resistiu "Ida-e-volta OK em 100, 500, 1000 bytes; mesmo texto gera tokens distintos" "info"
    return 0
}
