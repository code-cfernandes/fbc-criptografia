# O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
# Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
# autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
# estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
# keystream aleatório deve ter todos esses indicadores perto de zero/50%.
AtaqueAutocorrelacao() {
    ATQ_NOME="Autocorrelação e periodicidade do keystream"

    # Reduzido de 8192 para 2048 bytes (bash é ordens de magnitude mais lento).
    # 2048 mantém o limite fFBC de 0.10 a ~4.5 desvios-padrão de ruído
    # (SE ~ 1/sqrt(n)), evitando falsos positivos do limiar calibrado p/ 8192.
    local tamanho=$(( 2048 * FBC_ESCALA ))
    local tamanho_bloco=32

    local -a chave=()
    local -a iv=()
    string_to_bytes chave "$(alvo_chave_de_teste)"
    util_random_bytes iv "$(alvo_tamanho_iv)"

    local -a ks=()
    alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "enc" "$tamanho"

    local n=${#ks[@]}
    local ks_str="${ks[*]}"

    # Correlação (Pearson) entre a série e ela mesma deslocada de `lag`.
    local prog='BEGIN {
        n = split(data, a, " ")
        if (n <= lag) { print "0.000000"; exit }
        s = 0; for (i = 1; i <= n; i++) s += a[i]
        m = s / n
        den = 0; for (i = 1; i <= n; i++) den += (a[i] - m) * (a[i] - m)
        num = 0; for (i = 1; i <= n - lag; i++) num += (a[i] - m) * (a[i + lag] - m)
        if (den > 0) printf "%.6f", num / den; else printf "0.000000"
    }'

    local serial serial_abs
    serial=$(awk -v lag=1 -v data="$ks_str" "$prog")
    serial_abs=$(awk -v v="$serial" 'BEGIN { printf "%.6f", (v < 0 ? -v : v) }')

    local suspeitos=""
    local lag c c_abs
    for lag in 2 4 8 16 32 64 128 256; do
        c=$(awk -v lag="$lag" -v data="$ks_str" "$prog")
        c_abs=$(awk -v v="$c" 'BEGIN { printf "%.6f", (v < 0 ? -v : v) }')
        if util_maior "$c_abs" 0.10; then
            if [ -n "$suspeitos" ]; then
                suspeitos+=", "
            fi
            suspeitos+="$lag"
        fi
    done

    local -A vistos=()
    local blocos_repetidos=0 num_blocos=0 i j bloco
    for (( i = 0; i < n; i += tamanho_bloco )); do
        bloco=""
        for (( j = i; j < i + tamanho_bloco && j < n; j++ )); do
            bloco+="${ks[j]} "
        done
        num_blocos=$(( num_blocos + 1 ))
        if [ -n "${vistos[$bloco]:-}" ]; then
            blocos_repetidos=$(( blocos_repetidos + 1 ))
        else
            vistos[$bloco]=1
        fi
    done

    local uns=0
    for (( i = 0; i < n; i++ )); do
        uns=$(( uns + $(util_contar_bits "${ks[i]}") ))
    done
    local fracao_uns
    fracao_uns=$(util_div "$uns" $(( n * 8 )) 6)

    local -a problemas=()
    if util_maior "$serial_abs" 0.10; then
        problemas+=("correlação serial=$(util_fmt 3 "$serial")")
    fi
    if [ -n "$suspeitos" ]; then
        problemas+=("autocorrelação em lag(s) $suspeitos")
    fi
    if [ "$blocos_repetidos" -gt 0 ]; then
        problemas+=("$blocos_repetidos bloco(s) de $tamanho_bloco bytes repetido(s)")
    fi
    if util_menor "$fracao_uns" 0.45 || util_maior "$fracao_uns" 0.55; then
        problemas+=("balanço de bits=$(util_pct "$uns" $(( n * 8 )) 1)% de 1s")
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
        res_resistiu "serial=$(util_fmt 3 "$serial"), nenhum lag com correlação >10%, 0 blocos repetidos em $num_blocos, $(util_pct "$uns" $(( n * 8 )) 1)% de bits 1" "info"
    fi
    return 0
}
