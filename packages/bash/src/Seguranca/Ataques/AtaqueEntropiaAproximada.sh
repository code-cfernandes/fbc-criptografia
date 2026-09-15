# AtaqueEntropiaAproximada
#
# Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
# previsibilidade local: para uma sequência aleatória, a chance de repetir um
# bloco de m bits deve cair suavemente conforme m cresce. Estruturas
# periódicas/recorrentes produzem ApEn anômala.
#
# O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
# um valor esperado teórico. Comparamos o keystream com um CONTROLE de
# random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
# estatisticamente indistinguíveis.

AtaqueEntropiaAproximada() {
    ATQ_NOME="Entropia aproximada (ApEn vs controle aleatório)"

    # PHP usava tamanho=4096, controles=12, amostras=3; reduzido.
    local tamanho=$(( 256 * FBC_ESCALA ))
    local m=8
    local controles=$(( 6 * FBC_ESCALA ))
    local amostrasKeystream=$(( 2 * FBC_ESCALA ))
    local limiteZ=5.0

    local chave
    string_to_bytes chave "$(alvo_chave_de_teste)"

    # Gera as amostras: controles aleatórios + keystreams, todas como arrays
    # de bytes decimais.
    local -a amostrasBytes=()
    local -a rb
    local c k i b byte
    for (( c = 0; c < controles; c++ )); do
        util_random_bytes rb "$tamanho"
        amostrasBytes+=("${rb[*]}")
    done
    local -a iv ks
    for (( k = 0; k < amostrasKeystream; k++ )); do
        util_random_bytes iv "$(alvo_tamanho_iv)"
        alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "101 110 99" "$tamanho"
        amostrasBytes+=("${ks[*]}")
    done

    # chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1).
    local -a chis=()
    local s
    for (( s = 0; s < ${#amostrasBytes[@]}; s++ )); do
        local -a bytes=(${amostrasBytes[s]})
        local -a bits=()
        for (( i = 0; i < ${#bytes[@]}; i++ )); do
            byte=${bytes[i]}
            for (( b = 7; b >= 0; b-- )); do
                bits+=( $(( (byte >> b) & 1 )) )
            done
        done
        local n=${#bits[@]}

        # phi(m) e phi(m+1)
        local -a phiVals=()
        local mm
        for mm in "$m" $(( m + 1 )); do
            local -A contagem=()
            local janelas=$(( n - mm + 1 ))
            local i2 j v
            for (( i2 = 0; i2 < janelas; i2++ )); do
                v=0
                for (( j = 0; j < mm; j++ )); do
                    v=$(( (v << 1) | bits[i2+j] ))
                done
                contagem[$v]=$(( ${contagem[$v]:-0} + 1 ))
            done
            local lista=""
            for v in "${!contagem[@]}"; do
                lista+="${contagem[$v]} "
            done
            local soma
            soma=$(awk -v janelas="$janelas" -v lista="$lista" 'BEGIN {
                split(lista, cnt, " ");
                s = 0;
                for (i in cnt) {
                    if (cnt[i] == "") continue;
                    p = cnt[i] / janelas;
                    s += p * log(p);
                }
                printf "%.10f", s;
            }')
            phiVals+=("$soma")
        done

        local apen chi2
        apen=$(awk -v a="${phiVals[0]}" -v b="${phiVals[1]}" 'BEGIN { printf "%.10f", a - b }')
        chi2=$(awk -v n="$n" -v apen="$apen" 'BEGIN { printf "%.6f", 2 * n * (log(2) - apen) }')
        chis+=("$chi2")
    done

    # Separa controles e keystream.
    local -a chiControle=() chiKeystream=()
    for (( c = 0; c < controles; c++ )); do
        chiControle+=("${chis[c]}")
    done
    for (( k = 0; k < amostrasKeystream; k++ )); do
        chiKeystream+=("${chis[controles+k]}")
    done

    local mediaControle desvioControle mediaKeystream z
    read -r mediaControle desvioControle mediaKeystream z <<< "$(awk \
        -v ctrl="$(printf '%s ' "${chiControle[@]}")" \
        -v ksm="$(printf '%s ' "${chiKeystream[@]}")" 'BEGIN {
            split(ctrl, a, " ");
            nc = 0; sc = 0;
            for (i in a) { if (a[i] == "") continue; nc++; sc += a[i]; }
            mc = nc > 0 ? sc / nc : 0;
            var = 0;
            for (i in a) { if (a[i] == "") continue; var += (a[i] - mc) ^ 2; }
            sd = nc > 1 ? sqrt(var / (nc - 1)) : 0;

            split(ksm, b, " ");
            nk = 0; sk = 0;
            for (i in b) { if (b[i] == "") continue; nk++; sk += b[i]; }
            mk = nk > 0 ? sk / nk : 0;

            z = sd > 0 ? (mk - mc) / sd : 0;
            printf "%.6f %.6f %.6f %.6f", mc, sd, mk, z;
        }')"

    local absz
    absz=$(awk -v z="$z" 'BEGIN { print (z < 0 ? -z : z) }')

    local vulneravel=0
    if util_maior "$absz" "$limiteZ"; then
        vulneravel=1
    fi

    local detalhes
    detalhes="chi2 keystream=$(util_fmt 1 "$mediaKeystream"), controle=$(util_fmt 1 "$mediaControle") (sd=$(util_fmt 1 "$desvioControle")), z=$(util_fmt 2 "$z") (limite=${limiteZ})"
    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "media"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
