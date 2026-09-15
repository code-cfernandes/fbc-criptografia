# Ida-e-volta (round trip).
#
# Não é bem um "ataque" - é a checagem de sanidade básica: encrypt seguido
# de decrypt precisa devolver o texto original, em qualquer tamanho.
# Fica na suíte porque um bug de ida-e-volta geralmente esconde um bug de
# segurança mais sério por trás.
#
# Adaptação bash: tamanhoMaximo reduzido de 130 para 8 (× FBC_ESCALA); o
# texto é só 'Q', então o resultado pode ser capturado via $(...) sem
# problemas de byte NUL.

AtaqueIdaEVolta() {
    ATQ_NOME="Ida-e-volta (round trip)"

    local tamanho_maximo=$(( 8 * FBC_ESCALA ))
    local -a falhas=()
    local len k texto token decifrado

    for (( len = 0; len <= tamanho_maximo; len++ )); do
        texto=""
        for (( k = 0; k < len; k++ )); do
            texto+="Q"
        done

        if token=$(alvo_encrypt "$texto" 2>/dev/null); then
            if decifrado=$(alvo_decrypt "$token" 2>/dev/null); then
                if [ "$decifrado" != "$texto" ]; then
                    falhas+=("$len")
                fi
            else
                falhas+=("$len (erro: decrypt falhou)")
            fi
        else
            falhas+=("$len (erro: encrypt falhou)")
        fi
    done

    if [ "${#falhas[@]}" -gt 0 ]; then
        local primeiras
        primeiras=$(printf '%s, ' "${falhas[@]:0:10}")
        primeiras=${primeiras%, }
        res_vulneravel "Falhou em ${#falhas[@]} tamanho(s): $primeiras" "critica"
        return 0
    fi

    res_resistiu "Todos os $(( tamanho_maximo + 1 )) tamanhos (0 a $tamanho_maximo) OK" "info"
    return 0
}
