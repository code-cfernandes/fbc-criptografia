# AtaqueDiferencialKeystream
#
# Criptanálise diferencial no keystream: com uma diferença FIXA (1 bit) no
# IV, coleta as diferenças de saída entre ks(iv) e ks(iv ^ delta). Numa cifra
# boa, essas diferenças são uniformes e únicas. Sinaliza:
#  - bits de saída que NUNCA mudam (ou mudam sempre) para essa diferença;
#  - diferenças de saída que se REPETEM (diferencial de alta probabilidade),
#    que é o insumo básico de um ataque diferencial.

AtaqueDiferencialKeystream() {
    ATQ_NOME="Diferencial do keystream (delta fixo no IV)"

    # PHP usava 2000 amostras; reduzido.
    local amostras=$(( 100 * FBC_ESCALA ))
    local tamanhoBloco=32
    local tamanhoIv
    tamanhoIv=$(alvo_tamanho_iv)

    # Chave aleatória de 32 bytes (tamanho da chave de teste).
    local -a key=()
    util_random_bytes key 32

    # Delta: exatamente 1 bit em uma posição aleatória do IV.
    local -a delta=()
    local i
    for (( i = 0; i < tamanhoIv; i++ )); do
        delta[i]=0
    done
    local posDelta bitDelta
    posDelta=$(util_random_int 0 $(( tamanhoIv - 1 )))
    bitDelta=$(util_random_int 0 7)
    delta[posDelta]=$(( 1 << bitDelta ))

    local totalBits=$(( tamanhoBloco * 8 ))
    local -a sempreZero=() sempreUm=()
    for (( i = 0; i < totalBits; i++ )); do
        sempreZero[i]=1
        sempreUm[i]=1
    done

    local -A deltas=()
    local -a iv iv2 ks1 ks2 d
    local p b byte idx
    for (( i = 0; i < amostras; i++ )); do
        util_random_bytes iv "$tamanhoIv"
        for (( p = 0; p < tamanhoIv; p++ )); do
            iv2[p]=$(( iv[p] ^ delta[p] ))
        done

        alvo_gerar_keystream_bruto ks1 "${key[*]}" "${iv[*]}" "101 110 99" "$tamanhoBloco"
        alvo_gerar_keystream_bruto ks2 "${key[*]}" "${iv2[*]}" "101 110 99" "$tamanhoBloco"
        for (( p = 0; p < tamanhoBloco; p++ )); do
            d[p]=$(( ks1[p] ^ ks2[p] ))
        done
        deltas["${d[*]}"]=1

        for (( p = 0; p < tamanhoBloco; p++ )); do
            byte=${d[p]}
            for (( b = 0; b < 8; b++ )); do
                idx=$(( p * 8 + b ))
                if [ "$(( (byte >> b) & 1 ))" -eq 1 ]; then
                    sempreZero[idx]=0
                else
                    sempreUm[idx]=0
                fi
            done
        done
    done

    local bitsFixos=0
    for (( i = 0; i < totalBits; i++ )); do
        if [ "${sempreZero[i]}" -eq 1 ] || [ "${sempreUm[i]}" -eq 1 ]; then
            bitsFixos=$(( bitsFixos + 1 ))
        fi
    done
    local colisoes=$(( amostras - ${#deltas[@]} ))

    local vulneravel=0
    if [ "$bitsFixos" -gt 0 ] || [ "$colisoes" -gt 0 ]; then
        vulneravel=1
    fi

    local detalhes="delta de 1 bit no IV: ${bitsFixos} bit(s) de saída fixo(s), ${colisoes} diferencial(is) repetido(s) em ${amostras} amostras"
    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
