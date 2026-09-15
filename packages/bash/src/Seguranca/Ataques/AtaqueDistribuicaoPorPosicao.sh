# AtaqueDistribuicaoPorPosicao
#
# O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
# bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
# soma global pareça uniforme (o viés de uma posição se dilui entre as 32).

AtaqueDistribuicaoPorPosicao() {
    ATQ_NOME="Distribuição de bytes por posição do bloco"

    # PHP usava 2000 blocos; reduzido.
    local amostrasDeBlocos=$(( 200 * FBC_ESCALA ))
    local tamanhoBloco=32

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    # Contagens achatadas: índice p*256 + valor.
    local -a contagens=()
    local p v i
    for (( p = 0; p < tamanhoBloco; p++ )); do
        for (( v = 0; v < 256; v++ )); do
            contagens[p*256+v]=0
        done
    done

    local -a iv ks
    for (( i = 0; i < amostrasDeBlocos; i++ )); do
        util_random_bytes iv "$(alvo_tamanho_iv)"
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanhoBloco"
        for (( p = 0; p < tamanhoBloco; p++ )); do
            v=${ks[p]}
            contagens[p*256+v]=$(( contagens[p*256+v] + 1 ))
        done
    done

    local esperado
    esperado=$(util_div "$amostrasDeBlocos" 256 8)

    local problemas=""
    local qtd_problemas=0
    local pior=0.0
    local lista chi2 z
    for (( p = 0; p < tamanhoBloco; p++ )); do
        lista=""
        for (( v = 0; v < 256; v++ )); do
            lista+="${contagens[p*256+v]} "
        done
        read -r chi2 z <<< "$(awk -v lista="$lista" -v esp="$esperado" 'BEGIN {
            split(lista, c, " ");
            q = 0;
            for (i in c) {
                if (c[i] == "") continue;
                d = c[i] - esp;
                q += d * d / esp;
            }
            z = (q - 255) / sqrt(510);
            printf "%.1f %.3f", q, z;
        }')"
        if util_maior "$chi2" "$pior"; then
            pior=$chi2
        fi
        if util_maior "$z" 4.0; then
            qtd_problemas=$(( qtd_problemas + 1 ))
            problemas+="posição ${p} chi2=${chi2}; "
        fi
    done

    if [ "$qtd_problemas" -gt 0 ]; then
        res_vulneravel "${problemas%; }" "media"
    else
        res_resistiu "Todas as ${tamanhoBloco} posições uniformes (pior chi2=${pior}, esperado ~255)" "info"
    fi
    return 0
}
