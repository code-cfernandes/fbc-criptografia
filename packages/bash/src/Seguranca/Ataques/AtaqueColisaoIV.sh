# Se o mesmo IV aparece duas vezes com a mesma KEY, a cifra perde as
# garantias de confidencialidade (keystream reusado = "two-time pad").
# Gera muitos tokens do MESMO texto e verifica se os IVs nunca colidem.
#
# Amostra reduzida para bash: 100 * FBC_ESCALA gerações.

AtaqueColisaoIV() {
    ATQ_NOME="Colisão de IV"

    local geracoes=$(( 100 * FBC_ESCALA ))

    local prefixo
    prefixo=$(alvo_prefixo)

    local -A vistos=()
    local colisoes=0
    local i token
    for (( i = 0; i < geracoes; i++ )); do
        token=$(alvo_encrypt 'MESMO_TEXTO_SEMPRE')

        local -a dec
        alvo_base64url_decode dec "${token:${#prefixo}}"

        local -a integridade ciphertext iv
        alvo_decompor integridade ciphertext iv "${dec[*]}"
        local iv_str="${iv[*]}"

        if [ -n "${vistos[$iv_str]+x}" ]; then
            colisoes=$(( colisoes + 1 ))
        fi
        vistos[$iv_str]=1
    done

    if [ "$colisoes" -gt 0 ]; then
        res_vulneravel "$colisoes colisão(ões) de IV em $geracoes gerações" critica
    else
        res_resistiu "0 colisões em $geracoes gerações"
    fi
    return 0
}
