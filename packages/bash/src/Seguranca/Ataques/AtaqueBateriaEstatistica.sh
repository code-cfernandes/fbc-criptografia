# Bateria estatística no keystream (inspirada em NIST SP800-22): frequência
# global (monobit), frequência por posição de bit, teste de runs e frequência
# por bloco. Diferente do qui-quadrado de bytes, aqui o foco é o nível de BIT
# e a estrutura de sequência - vieses que a contagem de bytes pode mascarar.
#
# Usa z-scores com limite conservador (4 desvios) em vez de p-valores exatos,
# pra não depender de funções numéricas especiais.
AtaqueBateriaEstatistica() {
    ATQ_NOME="Bateria estatística de bits (monobit/runs/blocos)"

    # Reduzido de 16384 para ~1024 bytes (bash é ordens de magnitude mais lento).
    local tamanho=$(( 1024 * FBC_ESCALA ))
    local z_limite=4.0

    local -a chave=()
    local -a iv=()
    string_to_bytes chave "$(alvo_chave_de_teste)"
    util_random_bytes iv "$(alvo_tamanho_iv)"

    local -a ks=()
    alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "enc" "$tamanho"
    if [ ${#ks[@]} -eq 0 ]; then
        res_skip "Alvo não expõe gerar_keystream_bruto."
        return 0
    fi

    local -a bits=()
    local i b byte
    for (( i = 0; i < ${#ks[@]}; i++ )); do
        byte=${ks[i]}
        for (( b = 7; b >= 0; b-- )); do
            bits+=( $(( (byte >> b) & 1 )) )
        done
    done
    local n=${#bits[@]}
    local -a problemas=()

    # 1) Monobit: soma +1/-1
    local soma=0
    for (( i = 0; i < n; i++ )); do
        if [ "${bits[i]}" -eq 1 ]; then
            soma=$(( soma + 1 ))
        else
            soma=$(( soma - 1 ))
        fi
    done
    local abs_soma=$(( soma < 0 ? -soma : soma ))
    local z_monobit
    z_monobit=$(awk -v s="$abs_soma" -v n="$n" 'BEGIN { printf "%.4f", s / sqrt(n) }')
    if util_maior "$z_monobit" "$z_limite"; then
        problemas+=("monobit z=$(util_fmt 2 "$z_monobit")")
    fi

    # 2) Frequência por posição de bit
    local -a uns_pos=(0 0 0 0 0 0 0 0)
    local -a conta_pos=(0 0 0 0 0 0 0 0)
    for (( i = 0; i < ${#ks[@]}; i++ )); do
        byte=${ks[i]}
        for (( b = 0; b < 8; b++ )); do
            if [ $(( (byte >> b) & 1 )) -eq 1 ]; then
                uns_pos[b]=$(( uns_pos[b] + 1 ))
            fi
            conta_pos[b]=$(( conta_pos[b] + 1 ))
        done
    done
    local pos_viesadas=""
    for (( b = 0; b < 8; b++ )); do
        local frac z
        frac=$(util_div "${uns_pos[b]}" "${conta_pos[b]}" 10)
        z=$(awk -v f="$frac" -v c="${conta_pos[b]}" 'BEGIN { d = f - 0.5; if (d < 0) d = -d; printf "%.4f", d / (0.5 / sqrt(c)) }')
        if util_maior "$z" "$z_limite"; then
            if [ -n "$pos_viesadas" ]; then
                pos_viesadas+=", "
            fi
            pos_viesadas+="$b"
        fi
    done
    if [ -n "$pos_viesadas" ]; then
        problemas+=("viés por posição de bit: $pos_viesadas")
    fi

    # 3) Runs test
    local soma_bits=0
    for (( i = 0; i < n; i++ )); do
        soma_bits=$(( soma_bits + bits[i] ))
    done
    local pi
    pi=$(util_div "$soma_bits" "$n" 10)
    local z_runs=0.0000
    local cond
    cond=$(awk -v p="$pi" -v n="$n" 'BEGIN { d = p - 0.5; if (d < 0) d = -d; print (d < 2 / sqrt(n)) ? 1 : 0 }')
    if [ "$cond" -eq 1 ]; then
        local runs=1
        for (( i = 1; i < n; i++ )); do
            if [ "${bits[i]}" -ne "${bits[i - 1]}" ]; then
                runs=$(( runs + 1 ))
            fi
        done
        z_runs=$(awk -v runs="$runs" -v n="$n" -v pi="$pi" 'BEGIN {
            esp = 2 * n * pi * (1 - pi)
            des = 2 * sqrt(2 * n) * pi * (1 - pi)
            if (des == 0) { print "0.0000" } else { d = runs - esp; if (d < 0) d = -d; printf "%.4f", d / des }
        }')
        if util_maior "$z_runs" "$z_limite"; then
            problemas+=("runs z=$(util_fmt 2 "$z_runs")")
        fi
    fi

    # 4) Frequência por bloco (M = 128 bits)
    local m=128
    local num_blocos=$(( n / m ))
    local chi=0.0000
    local z_blocos=0.0000
    if [ "$num_blocos" -gt 0 ]; then
        local uns_list=""
        local blk j uns
        for (( blk = 0; blk < num_blocos; blk++ )); do
            uns=0
            for (( j = 0; j < m; j++ )); do
                uns=$(( uns + bits[blk * m + j] ))
            done
            uns_list+="$uns "
        done
        chi=$(awk -v lista="$uns_list" -v m="$m" 'BEGIN {
            cnt = split(lista, arr, " ")
            chi = 0
            for (i = 1; i <= cnt; i++) { d = arr[i] / m - 0.5; chi += d * d }
            chi *= 4 * m
            printf "%.4f", chi
        }')
        z_blocos=$(awk -v chi="$chi" -v nb="$num_blocos" 'BEGIN { printf "%.4f", (chi - nb) / sqrt(2 * nb) }')
        if util_maior "$z_blocos" "$z_limite"; then
            problemas+=("frequência por bloco chi2=$(util_fmt 1 "$chi")")
        fi
    fi

    if [ ${#problemas[@]} -gt 0 ]; then
        local texto_problemas=""
        local p
        for p in "${problemas[@]}"; do
            if [ -n "$texto_problemas" ]; then
                texto_problemas+="; "
            fi
            texto_problemas+="$p"
        done
        res_vulneravel "$texto_problemas" "media"
    else
        res_resistiu "monobit z=$(util_fmt 2 "$z_monobit"), runs z=$(util_fmt 2 "$z_runs"), blocos chi2=$(util_fmt 1 "$chi") - todos abaixo do limite z=$(util_fmt 0 "$z_limite")" "info"
    fi
    return 0
}
