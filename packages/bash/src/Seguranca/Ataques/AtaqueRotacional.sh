# Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
# de key/iv, então keystream(rot(key), rot(iv)) seria uma rotação de
# keystream(key, iv) - uma estrutura explorável. Testa todas as rotações de
# byte (31, já que a chave tem 32 bytes) e também coincidência direta.
AtaqueRotacional() {
    ATQ_NOME="Rotacional/slide (simetria por rotação)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho=32
    local tamanho_iv
    tamanho_iv=$(alvo_tamanho_iv)

    local -a chave
    string_to_bytes chave "$(alvo_chave_de_teste)"
    local len=${#chave[@]}

    local -a iv=()
    util_random_bytes iv "$tamanho_iv"

    local -a ks1=()
    alvo_gerar_keystream_bruto ks1 "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho"
    if [ "${#ks1[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a coincidencias=()
    local k i
    for (( k = 1; k < len; k++ )); do
        local -a chave_r=()
        for (( i = 0; i < len; i++ )); do
            chave_r+=( "${chave[(i + k) % len]}" )
        done
        local -a iv_r=()
        for (( i = 0; i < tamanho_iv; i++ )); do
            iv_r+=( "${iv[(i + k) % tamanho_iv]}" )
        done

        local -a ks2=()
        alvo_gerar_keystream_bruto ks2 "${chave_r[*]}" "${iv_r[*]}" "101 110 99" "$tamanho"

        if [ "${ks2[*]}" = "${ks1[*]}" ]; then
            coincidencias+=("rotação $k: keystream idêntico")
            continue
        fi

        local -a alvo_rot=()
        for (( i = 0; i < 32; i++ )); do
            alvo_rot+=( "${ks1[(i + k) % 32]}" )
        done
        local -a ks2_ini=("${ks2[@]:0:32}")
        if [ "${ks2_ini[*]}" = "${alvo_rot[*]}" ]; then
            coincidencias+=("rotação $k: keystream rotacionado")
        fi
    done

    local vulneravel=0
    if [ "${#coincidencias[@]}" -gt 0 ]; then
        vulneravel=1
    fi

    if [ "$vulneravel" -eq 1 ]; then
        local lista
        lista=$(printf '%s; ' "${coincidencias[@]:0:5}")
        lista=${lista%; }
        res_vulneravel "Simetria rotacional encontrada: $lista" "critica"
    else
        res_resistiu "Nenhuma das $(( len - 1 )) rotações de byte reproduziu o keystream" "info"
    fi
    return 0
}
