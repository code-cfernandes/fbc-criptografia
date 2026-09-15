# Teste serial: frequência de padrões SOBREPOSTOS de m bits (m=2,3,4). Um
# gerador bom distribui todos os 2^m padrões de forma uniforme. Estruturas
# locais (certos pares/triplas de bits que nunca ou quase nunca ocorrem)
# aparecem aqui mesmo quando a contagem global de bytes parece uniforme.
#
# Adaptação bash: amostras reduzidas de 4096 para 500 bytes (×FBC_ESCALA).
AtaqueSerialBits() {
    ATQ_NOME="Teste serial (padrões de bits sobrepostos)"

    local tamanho=$(( 500 * FBC_ESCALA ))
    local -a ordens=(2 3 4)

    local -a key iv ks bits
    string_to_bytes key "$(alvo_chave_de_teste)"
    util_random_bytes iv 16
    alvo_gerar_keystream_bruto ks "${key[*]}" "${iv[*]}" "101 110 99" "$tamanho"
    if [ "${#ks[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerarKeystreamBruto."
        return 0
    fi

    bits=()
    local byte b
    for byte in "${ks[@]}"; do
        for (( b = 7; b >= 0; b-- )); do
            bits+=( $(( (byte >> b) & 1 )) )
        done
    done
    local n=${#bits[@]}

    local problemas=""
    local m total janelas i j v
    local -a contagem
    local esperado chi2 dof z
    for m in "${ordens[@]}"; do
        total=$(( 1 << m ))
        janelas=$(( n - m + 1 ))
        contagem=()
        for (( i = 0; i < total; i++ )); do
            contagem[i]=0
        done

        for (( i = 0; i < janelas; i++ )); do
            v=0
            for (( j = 0; j < m; j++ )); do
                v=$(( (v << 1) | bits[i + j] ))
            done
            contagem[v]=$(( contagem[v] + 1 ))
        done

        esperado=$(util_div "$janelas" "$total" 6)
        chi2=$(awk -v e="$esperado" -v c="${contagem[*]}" 'BEGIN { n=split(c,a," "); s=0; for (k=1;k<=n;k++) { d=a[k]-e; s+=d*d/e } printf "%.6f", s }')
        dof=$(( total - 1 ))
        # Wilson-Hilferty: aproximação normal bem mais precisa para dof pequeno.
        z=$(awk -v c="$chi2" -v d="$dof" 'BEGIN { printf "%.6f", ((c/d)^(1/3) - (1 - 2/(9*d)))/sqrt(2/(9*d)) }')

        if util_maior "$z" "6.0"; then
            problemas+="m=$m chi2=$(util_fmt 1 "$chi2") (z=$(util_fmt 1 "$z")); "
        fi
    done

    if [ -n "$problemas" ]; then
        res_vulneravel "${problemas%; }" "media"
    else
        res_resistiu "Padrões sobrepostos de 2/3/4 bits com frequência uniforme"
    fi
    return 0
}
