# Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
# Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
# resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
#
#     keystream(key, iv) == keystream(key ^ d, iv ^ d)
#
# para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
# propriedade estrutural relevante: significa que key e iv não entram de
# forma independente na cifra, o que enfraquece o modelo de segurança (o IV
# deveria contribuir com entropia própria, não só deslocar a chave por XOR).
#
# Adaptação bash: tentativas reduzidas de 50 para 10 (×FBC_ESCALA).
AtaqueSeparacaoChaveIV() {
    ATQ_NOME="Separação chave/IV (invariância a key XOR iv)"

    local tentativas=$(( 10 * FBC_ESCALA ))
    local tamanhoBloco=32

    local chave_teste
    chave_teste="$(alvo_chave_de_teste)"
    local tamChave=${#chave_teste}
    local tamIv
    tamIv=$(alvo_tamanho_iv)

    local -a key0 iv0 primeiro
    string_to_bytes key0 "$chave_teste"
    util_random_bytes iv0 "$tamIv"
    alvo_gerar_keystream_bruto primeiro "${key0[*]}" "${iv0[*]}" "101 110 99" "$tamanhoBloco"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerarKeystreamBruto."
        return 0
    fi

    local confirmacoes=0
    local t p
    local -a chave iv d chave2 iv2 ks1 ks2
    for (( t = 0; t < tentativas; t++ )); do
        util_random_bytes chave "$tamChave"
        util_random_bytes iv "$tamIv"
        util_random_bytes d "$tamIv"

        chave2=()
        for (( p = 0; p < tamChave; p++ )); do
            chave2+=( $(( chave[p] ^ d[p % tamIv] )) )
        done
        iv2=()
        for (( p = 0; p < tamIv; p++ )); do
            iv2+=( $(( iv[p] ^ d[p] )) )
        done

        alvo_gerar_keystream_bruto ks1 "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanhoBloco"
        alvo_gerar_keystream_bruto ks2 "${chave2[*]}" "${iv2[*]}" "101 110 99" "$tamanhoBloco"

        if [ "${ks1[*]}" = "${ks2[*]}" ]; then
            confirmacoes=$(( confirmacoes + 1 ))
        fi
    done

    if [ "$confirmacoes" -eq "$tentativas" ]; then
        res_vulneravel "Confirmado em ${tentativas}/${tentativas}: keystream(key,iv) == keystream(key^d, iv^d). O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule." "media"
    else
        res_resistiu "Invariância não se confirmou (${confirmacoes}/${tentativas}); key e iv entram de forma independente."
    fi
    return 0
}
