# Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
# (qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext
# de cifra sólida deve parecer ruído mesmo com plaintext variado.
#
# Adaptação bash: ~30 amostras de 16 bytes (o original usa 200 de 64). O
# limite de qui-quadrado continua 350 (a distribuição tem 256 graus de
# liberdade) e a autocorrelação foi relaxada para 0.15, pois com apenas ~480
# bytes o erro-padrão de r é ~1/sqrt(480) ~ 0.046.
AtaqueCiphertextEstatistico() {
    ATQ_NOME="Estatística do ciphertext (chi²/runs/autocorrelação)"

    local amostras=$(( 30 * FBC_ESCALA ))
    local tamanho_texto=16
    local z_limite=4
    local chi2_limite=350
    local autocorr_limite=0.15

    local -a contagem=()
    local i
    for (( i = 0; i < 256; i++ )); do
        contagem[i]=0
    done

    local -a bytes=()
    local s
    for (( s = 0; s < amostras; s++ )); do
        local -a texto=()
        util_random_bytes texto "$tamanho_texto"

        local esc="" k v oct
        for (( k = 0; k < tamanho_texto; k++ )); do
            v=${texto[k]}
            if [ "$v" -eq 0 ]; then
                v=1
            fi
            printf -v oct '%03o' "$v"
            esc+="\\$oct"
        done
        local txt
        printf -v txt '%b' "$esc"

        local token
        if ! token=$(alvo_encrypt "$txt" 2>/dev/null); then
            continue
        fi

        local -a decoded=()
        if ! alvo_base64url_decode decoded "${token:3}"; then
            continue
        fi

        local -a integ=() ct=() iv=()
        alvo_decompor integ ct iv "${decoded[*]}"
        for v in "${ct[@]}"; do
            contagem[v]=$(( contagem[v] + 1 ))
            bytes+=("$v")
        done
    done

    local total=${#bytes[@]}
    if [ "$total" -eq 0 ]; then
        res_erro "Não foi possível obter ciphertexts."
        return 0
    fi

    local chi2
    chi2=$(awk -v cs="${contagem[*]}" -v t="$total" 'BEGIN {
        n = split(cs, a, " ");
        e = t / 256;
        chi = 0;
        for (i = 1; i <= n; i++) { d = a[i] - e; chi += (d * d) / e }
        printf "%.4f", chi
    }')

    local uns=0 n=0 runs=1
    local -a bits=()
    local b
    for b in "${bytes[@]}"; do
        for (( k = 7; k >= 0; k-- )); do
            local bit=$(( (b >> k) & 1 ))
            bits+=("$bit")
            uns=$(( uns + bit ))
            n=$(( n + 1 ))
        done
    done
    for (( i = 1; i < n; i++ )); do
        if [ "${bits[i]}" -ne "${bits[i - 1]}" ]; then
            runs=$(( runs + 1 ))
        fi
    done
    local pi z_runs
    pi=$(util_div "$uns" "$n" 10)
    z_runs=$(awk -v runs="$runs" -v n="$n" -v pi="$pi" 'BEGIN {
        e = 2 * n * pi * (1 - pi);
        d = 2 * sqrt(2 * n) * pi * (1 - pi);
        if (d == 0) { print "0" } else { x = runs - e; if (x < 0) x = -x; printf "%.4f", x / d }
    }')

    local autocorr
    autocorr=$(awk -v bs="${bytes[*]}" 'BEGIN {
        n = split(bs, a, " ");
        if (n < 2) { print "0"; exit }
        m = 0;
        for (i = 1; i <= n; i++) m += a[i];
        m /= n;
        num = 0; den = 0;
        for (i = 1; i <= n; i++) den += (a[i] - m) * (a[i] - m);
        for (i = 1; i < n; i++) num += (a[i] - m) * (a[i + 1] - m);
        if (den > 0) printf "%.4f", num / den; else print "0"
    }')

    local -a problemas=()
    if util_maior "$chi2" "$chi2_limite"; then
        problemas+=("qui-quadrado=$chi2 (>$chi2_limite suspeito)")
    fi
    if util_maior "$z_runs" "$z_limite"; then
        problemas+=("runs z=$(util_fmt 2 "$z_runs")")
    fi
    local abs_ac
    abs_ac=$(awk -v a="$autocorr" 'BEGIN { if (a < 0) a = -a; printf "%.4f", a }')
    if util_maior "$abs_ac" "$autocorr_limite"; then
        problemas+=("autocorrelação=$autocorr")
    fi

    if [ "${#problemas[@]}" -gt 0 ]; then
        local lista
        lista=$(printf '%s; ' "${problemas[@]}")
        lista=${lista%; }
        res_vulneravel "$lista" "media"
    else
        res_resistiu "qui-quadrado=$chi2 sobre $total bytes, runs z=$(util_fmt 2 "$z_runs"), autocorrelação=$autocorr - todos dentro do esperado" "info"
    fi
    return 0
}
