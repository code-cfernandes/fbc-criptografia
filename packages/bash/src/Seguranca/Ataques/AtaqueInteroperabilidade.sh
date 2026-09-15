# Vetores de referência (Known Answer Tests) e interoperabilidade.
#
# A mesma cifra é implementada em várias linguagens; este ataque fixa
# keystreams e tokens conhecidos: se a implementação bash divergir, ela não
# reproduz estes valores e o ataque acusa. Os tokens foram gerados com a chave
# de teste padrão; o IV é aleatório, mas fica embutido no token, então a
# decifragem é determinística.
AtaqueInteroperabilidade() {
    ATQ_NOME="Interoperabilidade e vetores conhecidos (KAT)"

    local -a chave
    string_to_bytes chave "$(printf 'K%.0s' $(seq 1 32))"

    local -a ivs=(
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "000102030405060708090a0b0c0d0e0f"
        "000102030405060708090a0b0c0d0e0f"
        "ffffffffffffffffffffffffffffffff"
        "30313233343536373839616263646566"
        "30313233343536373839616263646566"
    )
    local -a props=("enc" "enc" "mac" "enc" "mac" "enc" "enc" "mac")
    local -a tams=(32 64 32 32 64 32 64 32)
    local -a exps=(
        "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249"
        "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249a9b8fa2ec5a08abdae48729fe50aa1def4d6af963ecb11a46d1a4604046741a7"
        "ebaec6df127deb7dac57d584f86a13c53cfc74974da9f6594fd831acf3d07bb1"
        "0c8c9ba9ee81e6b9d00bd84b22c4180afd2a0c595f35a6be05b9d0a3ba37baf9"
        "2173c8774d071e983d895aeaa0cc2dd22d5da18b8427a98ee9ad89297eb03e0e961303b58b65bf2b6f48b7cfb2a04b1a7a9406f8a45605a1774d6fb8ddeda30d"
        "c2e2551794dea9cd8904550745adcc28baaf0179773eb0db171dc77701edae28"
        "ca36c5f105ea153f4dc6a591e97f7098bbc7c3aef2491423d9fb2ce612c84b7232009cb847d44cd2f72b47d0a293dd6227b96ce6cd2ba825e951b98e12819c0c"
        "22aec48f7ec4731e402cc64a1b31955d7757c75c5ce606e28eb47c8ad936af3f"
    )

    local -a textos=(
        ""
        "A"
        "TESTE"
        "mensagem de interoperabilidade entre linguagens"
    )
    local -a tokens=(
        "FBCbBmERldK0rQ3SAu1PxJ7drr2ie-jwhDLefEaGiBsJ_2autyPG4oSs6DXEM_w6-6x"
        "FBCo5OnvHbHG6nILqXCjGzVYo32jIC9I_PAqQ9CvRxggyiYKwhedK4ynN65_SSrE_mezQ"
        "FBCn7T3VBZFYnvG41Dx4VYn-tyKKd3QheLJ1kw7oDb9EhSUEfnTtlEN2Rxp1xaskppvmGSmeTI"
        "FBCqgHvQ_SGLjte-SDNMHt3LyNB8qGUfMxn_N1PqWGdQmyE4iHtA3k45aAygQnBpqAXYxlwIxkDumz3ln33vAttxUwIuYExCrG-LaYLBUVEyuX49X86mScMpOd3isnqYhU"
    )

    local -a falhas=()
    local i j

    for (( i = 0; i < ${#ivs[@]}; i++ )); do
        local -a iv_dec=()
        local iv_hex=${ivs[i]}
        for (( j = 0; j < ${#iv_hex}; j += 2 )); do
            iv_dec+=( $(( 16#${iv_hex:j:2} )) )
        done

        local prop
        if [ "${props[i]}" = "enc" ]; then
            prop="101 110 99"
        else
            prop="109 97 99"
        fi

        local -a ks=()
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv_dec[*]}" "$prop" "${tams[i]}"
        local obtido
        obtido=$(printf '%02x' "${ks[@]}")
        if [ "$obtido" != "${exps[i]}" ]; then
            falhas+=("keystream iv=${ivs[i]} prop=${props[i]} tam=${tams[i]}")
        fi
    done

    local saida
    for (( i = 0; i < ${#tokens[@]}; i++ )); do
        if ! saida=$(alvo_decrypt "${tokens[i]}" 2>/dev/null); then
            falhas+=("token rejeitado: \"${textos[i]}\"")
        elif [ "$saida" != "${textos[i]}" ]; then
            falhas+=("token não decifrou para \"${textos[i]}\"")
        fi
    done

    if [ "${#falhas[@]}" -gt 0 ]; then
        local lista
        lista=$(printf '%s; ' "${falhas[@]:0:5}")
        lista=${lista%; }
        res_vulneravel "${#falhas[@]} divergência(s) de interoperabilidade: $lista" "alta"
    else
        res_resistiu "${#ivs[@]} vetores de keystream e ${#tokens[@]} tokens de referência conferem" "info"
    fi
    return 0
}
