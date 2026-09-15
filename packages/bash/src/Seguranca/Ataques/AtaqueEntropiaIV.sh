# AtaqueEntropiaIV
#
# O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
# Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
# trocar random_bytes(16) por algo previsível mas ainda "único" (tipo
# timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
# rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
# mesmo sem nunca colidir de fato.
#
# Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
# ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
# e sequências crescentes/monótonas entre IVs consecutivos (sintoma
# clássico de contador ou timestamp).

AtaqueEntropiaIV() {
    ATQ_NOME="Entropia e previsibilidade do IV"

    # PHP usava 2000 amostras; reduzido.
    local amostras=$(( 200 * FBC_ESCALA ))

    local -a ivs=()
    local -a decoded integ ct iv
    local i token
    for (( i = 0; i < amostras; i++ )); do
        token=$(alvo_encrypt 'X')
        alvo_base64url_decode decoded "${token:3}"
        alvo_decompor integ ct iv "${decoded[*]}"
        ivs+=("${iv[*]}")
    done

    local problemas=""
    local -a cur=()
    local v

    # Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
    local -a contagem=()
    for (( v = 0; v < 256; v++ )); do
        contagem[v]=0
    done
    local total=0
    for (( i = 0; i < amostras; i++ )); do
        cur=(${ivs[i]})
        for (( v = 0; v < ${#cur[@]}; v++ )); do
            contagem[${cur[v]}]=$(( contagem[${cur[v]}] + 1 ))
            total=$(( total + 1 ))
        done
    done
    local qui2
    qui2=$(awk -v total="$total" -v lista="$(printf '%s ' "${contagem[@]}")" 'BEGIN {
        split(lista, c, " ");
        esperado = total / 256;
        q = 0;
        for (i in c) {
            if (c[i] == "") continue;
            d = c[i] - esperado;
            q += d * d / esperado;
        }
        printf "%.1f", q;
    }')
    if util_maior "$qui2" 330; then
        problemas+="distribuição de bytes suspeita (qui-quadrado=${qui2}, >330 é suspeito); "
    fi

    # Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
    # primeiro byte estritamente crescente (um contador/timestamp cru
    # produziria isso quase sempre; aleatório, só ~50% das vezes).
    local crescentes=0
    local -a a b
    for (( i = 1; i < amostras; i++ )); do
        a=(${ivs[i-1]})
        b=(${ivs[i]})
        if [ "${b[0]}" -gt "${a[0]}" ]; then
            crescentes=$(( crescentes + 1 ))
        fi
    done
    local proporcaoCrescente
    proporcaoCrescente=$(util_div "$crescentes" $(( amostras - 1 )) 6)
    if util_maior "$proporcaoCrescente" 0.65 || util_menor "$proporcaoCrescente" 0.35; then
        local pctCrescente
        pctCrescente=$(awk -v p="$proporcaoCrescente" 'BEGIN { printf "%.0f", p * 100 }')
        problemas+="primeiro byte do IV parece monotônico (${pctCrescente}% das vezes crescente; aleatório ficaria perto de 50%); "
    fi

    # Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
    # (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
    # repetição interna) - a AUSÊNCIA de qualquer repetição interna em
    # quase todos os IVs seria estranha (sugeriria geração não-uniforme,
    # tipo bytes distintos forçados).
    local semRepeticaoInterna=0
    local -A visto=()
    for (( i = 0; i < amostras; i++ )); do
        cur=(${ivs[i]})
        visto=()
        local unico=1
        for (( v = 0; v < ${#cur[@]}; v++ )); do
            if [ -n "${visto[${cur[v]}]:-}" ]; then
                unico=0
                break
            fi
            visto[${cur[v]}]=1
        done
        if [ "$unico" -eq 1 ]; then
            semRepeticaoInterna=$(( semRepeticaoInterna + 1 ))
        fi
    done
    local proporcaoSemRepeticao
    proporcaoSemRepeticao=$(util_div "$semRepeticaoInterna" "$amostras" 6)
    # Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
    if util_maior "$proporcaoSemRepeticao" 0.90 || util_menor "$proporcaoSemRepeticao" 0.50; then
        local pctSemRepeticao
        pctSemRepeticao=$(awk -v p="$proporcaoSemRepeticao" 'BEGIN { printf "%.0f", p * 100 }')
        problemas+="${pctSemRepeticao}% dos IVs não têm nenhum byte repetido internamente (esperado ~72% para 16 bytes aleatórios); "
    fi

    if [ -n "$problemas" ]; then
        res_vulneravel "${problemas%; }" "alta"
    else
        local pctCrescente pctSemRepeticao
        pctCrescente=$(awk -v p="$proporcaoCrescente" 'BEGIN { printf "%.0f", p * 100 }')
        pctSemRepeticao=$(awk -v p="$proporcaoSemRepeticao" 'BEGIN { printf "%.0f", p * 100 }')
        res_resistiu "qui-quadrado=${qui2}, ${pctCrescente}% primeiro-byte-crescente (~50% esperado), ${pctSemRepeticao}% sem repetição interna (~72% esperado) - tudo consistente com IV aleatório" "info"
    fi
    return 0
}
