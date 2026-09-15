# Integral (soma balanceada variando 1 byte de IV/chave).
#
# Ataque integral (square): fixa a chave e percorre TODOS os 256 valores de
# um byte do IV (e da chave), fazendo XOR de todos os keystreams resultantes.
#
# Numa função aleatória, o XOR de 256 saídas é uniforme, então cada byte da
# soma é zero com probabilidade 1/256. Se a cifra tiver difusão incompleta,
# a saída como função do byte variado fica "quase bijetiva" e a soma tende a
# zero MUITO mais que o acaso - um distinguisher clássico.
#
# Adaptação bash: tentativas reduzidas de 16 para 1 (× FBC_ESCALA) e
# posições de IV/chave de 8 para 2 cada - cada posição custa 256 gerações de
# keystream. A soma é feita byte a byte em array de decimais.

AtaqueIntegral() {
    ATQ_NOME="Integral (soma balanceada variando 1 byte de IV/chave)"

    if ! declare -F alvo_gerar_keystream_bruto >/dev/null; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local tamanho_bloco=32
    local posicoes_iv=2
    local posicoes_chave=2
    local tentativas=$(( 1 * FBC_ESCALA ))
    local limite_z=5.0

    local tam_iv tam_chave
    tam_iv=$(alvo_tamanho_iv)

    local -a chave_base=()
    string_to_bytes chave_base "$(alvo_chave_de_teste)"
    tam_chave=${#chave_base[@]}

    local -a primeiro=() ks=() xor_acc=() kk=() ii=()
    local iv
    util_random_bytes iv "$tam_iv"
    alvo_gerar_keystream_bruto primeiro "${chave_base[*]}" "${iv[*]}" "101 110 99" "$tamanho_bloco"
    if [ "${#primeiro[@]}" -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a distinguidores=()
    local zeros_total=0
    local bytes_total=0
    local t pos v k campo lim
    local zeros allzero
    local -a chave_r=() iv_base=()

    for (( t = 0; t < tentativas; t++ )); do
        util_random_bytes chave_r "$tam_chave"
        util_random_bytes iv_base "$tam_iv"

        local lim_iv=$(( posicoes_iv < tam_iv ? posicoes_iv : tam_iv ))
        local lim_key=$(( posicoes_chave < tam_chave ? posicoes_chave : tam_chave ))

        for campo in iv key; do
            if [ "$campo" = "iv" ]; then
                lim=$lim_iv
            else
                lim=$lim_key
            fi
            for (( pos = 0; pos < lim; pos++ )); do
                xor_acc=()
                for (( k = 0; k < tamanho_bloco; k++ )); do
                    xor_acc[k]=0
                done

                for (( v = 0; v < 256; v++ )); do
                    kk=("${chave_r[@]}")
                    ii=("${iv_base[@]}")
                    if [ "$campo" = "iv" ]; then
                        ii[pos]=$v
                    else
                        kk[pos]=$v
                    fi
                    alvo_gerar_keystream_bruto ks "${kk[*]}" "${ii[*]}" "101 110 99" "$tamanho_bloco"
                    for (( k = 0; k < tamanho_bloco; k++ )); do
                        xor_acc[k]=$(( xor_acc[k] ^ ks[k] ))
                    done
                done

                zeros=0
                allzero=1
                for (( k = 0; k < tamanho_bloco; k++ )); do
                    if [ "${xor_acc[k]}" -eq 0 ]; then
                        zeros=$(( zeros + 1 ))
                    else
                        allzero=0
                    fi
                done
                zeros_total=$(( zeros_total + zeros ))
                bytes_total=$(( bytes_total + tamanho_bloco ))

                if [ "$allzero" -eq 1 ]; then
                    if [ "$campo" = "iv" ]; then
                        distinguidores+=("iv[$pos]")
                    else
                        distinguidores+=("key[$pos]")
                    fi
                fi
            done
        done
    done

    local esperado desvio z
    esperado=$(awk -v b="$bytes_total" 'BEGIN { printf "%.4f", b * (1/256) }')
    desvio=$(awk -v b="$bytes_total" 'BEGIN { printf "%.6f", sqrt(b * (1/256) * (1 - 1/256)) }')
    z=$(awk -v zt="$zeros_total" -v e="$esperado" -v d="$desvio" 'BEGIN { if (d > 0) printf "%.4f", (zt - e) / d; else print "0" }')

    local vulneravel=0
    if [ "${#distinguidores[@]}" -gt 0 ] || util_maior "$z" "$limite_z"; then
        vulneravel=1
    fi

    if [ "${#distinguidores[@]}" -gt 0 ]; then
        local primeiros
        primeiros=$(printf '%s, ' "${distinguidores[@]:0:10}")
        primeiros=${primeiros%, }
        res_vulneravel "Soma balanceada (XOR zero) encontrada variando: $primeiros" "critica"
        return 0
    fi

    local z_fmt esperado_fmt
    z_fmt=$(awk -v v="$z" 'BEGIN { printf "%.2f", v }')
    esperado_fmt=$(awk -v v="$esperado" 'BEGIN { printf "%.1f", v }')
    local detalhe="bytes de saída zerados=$zeros_total (esperado ~$esperado_fmt, z=$z_fmt) em $bytes_total amostras; limite z=$limite_z"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhe" "media"
    else
        res_resistiu "$detalhe" "info"
    fi
    return 0
}
