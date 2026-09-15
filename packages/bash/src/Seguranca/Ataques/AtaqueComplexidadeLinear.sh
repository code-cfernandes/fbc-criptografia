# Berlekamp-Massey: calcula a complexidade linear (tamanho do menor LFSR que
# reproduz a sequência de bits). Para uma sequência aleatória de N bits, a
# complexidade fica perto de N/2. Se a cifra esconder estrutura linear (tipo
# um LFSR disfarçado), a complexidade cai MUITO abaixo disso - e aí a cifra
# seria atacável resolvendo um sistema linear em vez de força bruta.
#
# Amostra reduzida para bash: 2 * FBC_ESCALA amostras de 128 bits.

AtaqueComplexidadeLinear() {
    ATQ_NOME="Complexidade linear (Berlekamp-Massey)"

    local bits_por_amostra=128
    local amostras=$(( 2 * FBC_ESCALA ))
    local limite_relativo=0.40

    local -a chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a prop_arr
    string_to_bytes prop_arr "enc"
    local prop="${prop_arr[*]}"

    # gera um keystream inicial só pra confirmar que a camada está exposta
    local -a iv_primeiro
    util_random_bytes iv_primeiro 16
    local -a primeiro
    alvo_gerar_keystream_bruto primeiro "${chave[*]}" "${iv_primeiro[*]}" "$prop" 64

    local soma=0 pior=1
    local a
    for (( a = 0; a < amostras; a++ )); do
        local -a iv
        util_random_bytes iv 16
        local -a bytes
        alvo_gerar_keystream_bruto bytes "${chave[*]}" "${iv[*]}" "$prop" $(( bits_por_amostra / 8 ))

        # paraBits: converte os bytes em bits (MSB primeiro), até o limite.
        local -a bits=()
        local i b byte
        for (( i = 0; i < ${#bytes[@]} && ${#bits[@]} < bits_por_amostra; i++ )); do
            byte=${bytes[i]}
            for (( b = 7; b >= 0; b-- )); do
                bits+=($(( (byte >> b) & 1 )))
                if [ ${#bits[@]} -ge "$bits_por_amostra" ]; then break; fi
            done
        done

        # Berlekamp-Massey sobre GF(2).
        local n=${#bits[@]}
        local -a c=() bk=() tmp=()
        local j
        for (( j = 0; j < n; j++ )); do
            c[j]=0
            bk[j]=0
        done
        c[0]=1
        bk[0]=1
        local l=0 m=-1
        for (( i = 0; i < n; i++ )); do
            local d=${bits[i]}
            for (( j = 1; j <= l; j++ )); do
                d=$(( d ^ ( c[j] & bits[i - j] ) ))
            done

            if [ "$d" -eq 1 ]; then
                tmp=("${c[@]}")
                local shift=$(( i - m ))
                for (( j = 0; j + shift < n; j++ )); do
                    c[j + shift]=$(( c[j + shift] ^ bk[j] ))
                done
                if [ "$l" -le $(( i / 2 )) ]; then
                    l=$(( i + 1 - l ))
                    m=$i
                    bk=("${tmp[@]}")
                fi
            fi
        done

        local relativo
        relativo=$(util_div "$l" "$bits_por_amostra" 6)
        soma=$(awk -v s="$soma" -v r="$relativo" 'BEGIN { printf "%.6f", s + r }')
        if util_menor "$relativo" "$pior"; then
            pior=$relativo
        fi
    done

    local media
    media=$(util_div "$soma" "$amostras" 6)

    local vulneravel=0
    if util_menor "$pior" "$limite_relativo"; then
        vulneravel=1
    fi

    local media_pct pior_pct limite_pct
    media_pct=$(awk -v v="$media" 'BEGIN { printf "%.1f", v * 100 }')
    pior_pct=$(awk -v v="$pior" 'BEGIN { printf "%.1f", v * 100 }')
    limite_pct=$(awk -v v="$limite_relativo" 'BEGIN { printf "%.0f", v * 100 }')

    local detalhes="complexidade linear relativa: média=${media_pct}%, pior=${pior_pct}% de $bits_por_amostra bits (esperado ~50%; limite>=$limite_pct%)"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" critica
    else
        res_resistiu "$detalhes"
    fi
    return 0
}
