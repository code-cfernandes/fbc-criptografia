# AtaqueCorrelacaoPosicoes
#
# Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
# correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
# posições de saída é exatamente o tipo de estrutura que o antigo bug da
# "metade igual" produzia - e que a autocorrelação temporal pode não pegar.
#
# O coeficiente de Pearson é calculado com a fórmula inteira
#   r = (n*Σxy - Σx*Σy) / sqrt((n*Σx² - (Σx)²)(n*Σy² - (Σy)²))
# e só o valor final passa por awk, evitando float por amostra.

AtaqueCorrelacaoPosicoes() {
    ATQ_NOME="Correlação entre posições do bloco"

    # PHP usava 3000 amostras; reduzido para rodar em segundos.
    local amostras=$(( 200 * FBC_ESCALA ))
    local tamanhoBloco=32
    # O limiar de significância de |r| encolhe com 1/sqrt(n). Como reduzimos
    # n, reescalamos o limiar original (0.15 para n=3000) para manter a MESMA
    # taxa de falso-positivo - sem isso, 200 amostras acusariam ruído puro.
    local limiteCorrelacao
    limiteCorrelacao=$(awk -v l=0.15 -v n0=3000 -v n="$amostras" 'BEGIN { printf "%.6f", l * sqrt(n0 / n) }')

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    local -a blocos=()
    local -a iv ks
    local i pos
    for (( i = 0; i < amostras; i++ )); do
        util_random_bytes iv "$(alvo_tamanho_iv)"
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanhoBloco"
        for (( pos = 0; pos < tamanhoBloco; pos++ )); do
            blocos+=( "${ks[pos]}" )
        done
    done

    # Somas por posição (Σx e Σx²).
    local -a soma=() soma2=()
    local p v
    for (( p = 0; p < tamanhoBloco; p++ )); do
        soma[p]=0
        soma2[p]=0
    done
    for (( i = 0; i < amostras; i++ )); do
        for (( p = 0; p < tamanhoBloco; p++ )); do
            v=${blocos[i*tamanhoBloco+p]}
            soma[p]=$(( soma[p] + v ))
            soma2[p]=$(( soma2[p] + v * v ))
        done
    done

    local suspeitos=""
    local qtd_suspeitos=0
    local pior=0.0
    local a b sxy r absr
    for (( a = 0; a < tamanhoBloco; a++ )); do
        for (( b = a + 1; b < tamanhoBloco; b++ )); do
            sxy=0
            for (( i = 0; i < amostras; i++ )); do
                sxy=$(( sxy + blocos[i*tamanhoBloco+a] * blocos[i*tamanhoBloco+b] ))
            done
            read -r r absr <<< "$(awk \
                -v n="$amostras" -v sxy="$sxy" \
                -v sx="${soma[a]}" -v sy="${soma[b]}" \
                -v sx2="${soma2[a]}" -v sy2="${soma2[b]}" 'BEGIN {
                    num = n*sxy - sx*sy;
                    den = (n*sx2 - sx*sx) * (n*sy2 - sy*sy);
                    if (den <= 0) { printf "0 0" }
                    else { r = num/sqrt(den); printf "%.6f %.6f", r, (r < 0 ? -r : r) }
                }')"
            if util_maior "$absr" "$pior"; then
                pior=$absr
            fi
            if util_maior "$absr" "$limiteCorrelacao"; then
                qtd_suspeitos=$(( qtd_suspeitos + 1 ))
                if [ "$qtd_suspeitos" -le 10 ]; then
                    suspeitos+="posições ${a}-${b} (r=$(util_fmt 3 "$r")); "
                fi
            fi
        done
    done

    if [ "$qtd_suspeitos" -gt 0 ]; then
        res_vulneravel "${qtd_suspeitos} par(es) correlacionado(s): ${suspeitos%; }" "alta"
    else
        res_resistiu "Nenhum par de posições correlacionado acima de $(util_fmt 2 "$limiteCorrelacao") (pior |r|=$(util_fmt 3 "$pior"))" "info"
    fi
    return 0
}
