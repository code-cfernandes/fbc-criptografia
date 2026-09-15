# AtaqueCorrelacaoMesmoPlaintext
#
# O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV. Esse
# ataque vai além: verifica se os CIPHERTEXTS resultantes, embora venham do
# mesmo texto, se comportam como se fossem de textos diferentes (distância de
# Hamming média ~50%, sem nenhum padrão fixo entre eles).
#
# Se o IV está fazendo seu trabalho, cifrar "SEGREDO" N vezes deveria parecer,
# aos olhos de quem só vê o ciphertext, tão aleatório quanto cifrar N textos
# diferentes.

AtaqueCorrelacaoMesmoPlaintext() {
    ATQ_NOME="Correlação entre ciphertexts do mesmo plaintext"

    # Bash é ordens de magnitude mais lento: amostra reduzida (PHP usava 300).
    local amostras=$(( 30 * FBC_ESCALA ))
    local textoFixo='MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR'

    local -a ciphertexts=()
    local -a decoded integ ct iv
    local i token
    for (( i = 0; i < amostras; i++ )); do
        token=$(alvo_encrypt "$textoFixo")
        alvo_base64url_decode decoded "${token:3}"
        alvo_decompor integ ct iv "${decoded[*]}"
        ciphertexts+=("${ct[*]}")
    done

    # Confere que nenhum PAR de ciphertexts é idêntico (o que indicaria reuso
    # de IV+key, capturado de outro ângulo).
    local -A vistos=()
    local duplicatas=0 c
    for c in "${ciphertexts[@]}"; do
        if [ -n "${vistos[$c]:-}" ]; then
            duplicatas=$(( duplicatas + 1 ))
        else
            vistos[$c]=1
        fi
    done

    local -a primeiro=(${ciphertexts[0]})
    local len=${#primeiro[@]}

    # Compara pares aleatórios de ciphertexts (não todos contra todos, pra
    # manter o custo baixo) e mede a distância de Hamming média.
    local max_comp=$(( amostras * (amostras - 1) / 2 ))
    local comparacoes=$(( max_comp < 500 ? max_comp : 500 ))
    local soma_diff=0 soma_bits=0
    local a b j d
    for (( a = 0; a < comparacoes; a++ )); do
        i=$(util_random_int 0 $(( amostras - 1 )))
        j=$(util_random_int 0 $(( amostras - 1 )))
        if [ "$i" -eq "$j" ]; then
            continue
        fi
        d=$(util_bits_diferentes "${ciphertexts[i]}" "${ciphertexts[j]}")
        soma_diff=$(( soma_diff + d ))
        soma_bits=$(( soma_bits + len * 8 ))
    done

    local media=0.5
    if [ "$soma_bits" -gt 0 ]; then
        media=$(util_div "$soma_diff" "$soma_bits" 6)
    fi

    local vulneravel=0
    if util_menor "$media" 0.40 || util_maior "$media" 0.60 || [ "$duplicatas" -gt 0 ]; then
        vulneravel=1
    fi

    local pct
    pct=$(awk -v m="$media" 'BEGIN { printf "%.1f", m * 100 }')
    local detalhes
    detalhes="distância de Hamming média entre ciphertexts do mesmo texto: ${pct}% (esperado ~50%), ${duplicatas} duplicata(s) exata(s) em ${amostras} amostras"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
