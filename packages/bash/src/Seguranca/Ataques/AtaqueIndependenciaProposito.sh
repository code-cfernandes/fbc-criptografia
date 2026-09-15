# Independência entre keystreams de propósitos diferentes (enc x mac).
#
# A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a
# chave do MAC ('mac'). Se os dois streams não forem independentes, um
# atacante que recupere o keystream de dados (ataque de texto conhecido)
# pode derivar a chave do MAC e FORJAR tokens válidos.
#
# O teste procura dois sintomas de acoplamento:
#  1. a distância de Hamming média entre os streams deve ser ~50%;
#  2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
#     uma máscara fixa, o mac é 100% previsível a partir do enc.
#
# Adaptação bash: amostras reduzidas de 2000 para 50 (× FBC_ESCALA). Key e
# IV são arrays de decimais, então podem conter 0..255 normalmente.

AtaqueIndependenciaProposito() {
    ATQ_NOME="Independência entre keystreams de propósitos diferentes (enc x mac)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local amostras=$(( 50 * FBC_ESCALA ))
    local tamanho=32

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a primeiro=() ks=() enc=() mac=() x=()
    local iv
    util_random_bytes iv 16
    alvo_gerar_keystream_bruto primeiro "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a distancias=()
    declare -A mascaras=()
    local -a chave_r=() iv_r=()
    local i k diff

    for (( i = 0; i < amostras; i++ )); do
        util_random_bytes chave_r 32
        util_random_bytes iv_r 16

        alvo_gerar_keystream_bruto enc "${chave_r[*]}" "${iv_r[*]}" "101 110 99" "$tamanho"
        alvo_gerar_keystream_bruto mac "${chave_r[*]}" "${iv_r[*]}" "109 97 99" "$tamanho"

        diff=$(util_bits_diferentes "${enc[*]}" "${mac[*]}")
        distancias+=("$(util_div "$diff" $(( tamanho * 8 )))")

        x=()
        for (( k = 0; k < tamanho; k++ )); do
            x+=($(( enc[k] ^ mac[k] )))
        done
        mascaras["${x[*]}"]=1
    done

    local media
    media=$(printf '%s\n' "${distancias[@]}" | awk '{s+=$1} END { if (NR>0) printf "%.6f", s/NR; else print "0" }')
    local mascaras_distintas=${#mascaras[@]}
    local pct
    pct=$(awk -v m="$media" 'BEGIN { printf "%.1f", m * 100 }')

    local vulneravel=0
    if util_menor "$media" 0.40 || util_maior "$media" 0.60 || [ "$mascaras_distintas" -lt "$amostras" ]; then
        vulneravel=1
    fi

    local extra=""
    if [ "$mascaras_distintas" -lt "$amostras" ]; then
        extra=" - MÁSCARA REPETIDA: mac previsível a partir de enc!"
    fi
    local detalhe="Hamming médio enc x mac=${pct}% (esperado ~50%); ${mascaras_distintas} máscara(s) XOR distinta(s) em ${amostras} amostras${extra}"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhe" "critica"
    else
        res_resistiu "$detalhe" "info"
    fi
    return 0
}
