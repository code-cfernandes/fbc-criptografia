# Ida-e-volta com dados binários (inclui NUL).
#
# O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
# verdade: valores de byte, sequências aleatórias de vários tamanhos. Erros
# de manipulação de string (trim, encoding, NUL truncation) só aparecem com
# bytes arbitrários.
#
# Adaptação bash: bash NÃO consegue guardar 0x00 dentro de uma string (a
# variável trunca silenciosamente), então o valor 0 (NUL) fica de fora: os
# bytes testados são 1..255. Os dados entram na API via `printf -v` (que não
# trunca newline final) e a saída do decrypt é lida com `od`, que enxerga
# NUL/newline sem depender de strings bash.

AtaqueIdaEVoltaBinario() {
    ATQ_NOME="Ida-e-volta com dados binários (inclui NUL)"

    local tamanho_maximo=$(( 16 * FBC_ESCALA ))
    local -a falhas=()
    local len k v
    local texto token esc oct val
    local -a originais=() decifrados=()

    for (( len = 0; len <= tamanho_maximo; len++ )); do
        originais=()
        util_random_bytes originais "$len"
        # 0 (NUL) não sobrevive numa string bash: remapeia pra 1.
        esc=""
        for (( k = 0; k < len; k++ )); do
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
            # cripto_decrypt imprime um newline final de cortesia: remove.
            if [ "${#decifrados[@]}" -gt 0 ]; then
                decifrados=("${decifrados[@]:0:${#decifrados[@]}-1}")
            fi
            if [ "${decifrados[*]}" != "${originais[*]}" ]; then
                falhas+=("$len")
            fi
        else
            falhas+=("$len (erro: encrypt falhou)")
        fi
    done

    # Todos os valores de byte que o bash consegue representar (1..255).
    originais=()
    esc=""
    for (( v = 1; v <= 255; v++ )); do
        originais+=("$v")
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
            falhas+=("todos os 255 valores de byte (1..255)")
        fi
    else
        falhas+=("todos os 255 valores de byte (erro: encrypt falhou)")
    fi

    if [ "${#falhas[@]}" -gt 0 ]; then
        local primeiras
        primeiras=$(printf '%s, ' "${falhas[@]:0:10}")
        primeiras=${primeiras%, }
        res_vulneravel "Falhou em ${#falhas[@]} caso(s): $primeiras" "critica"
        return 0
    fi

    res_resistiu "Todos os tamanhos 0..$tamanho_maximo e os 255 valores de byte (1..255) preservados; 0/NUL excluído porque bash não representa NUL em strings" "info"
    return 0
}
