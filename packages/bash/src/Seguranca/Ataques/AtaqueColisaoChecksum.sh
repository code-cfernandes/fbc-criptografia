# Procura colisões no checksum() via paradoxo do aniversário: gera muitas
# mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
# propósito aqui - testar resistência a colisão é uma propriedade do
# ALGORITMO, independente de a chave ser secreta ou não; é assim que se
# testa qualquer função de hash/MAC na prática).
#
# Testa dois níveis:
# 1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
#    aparecer nunca com uma amostra viável de testar.
# 2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa é esperada
#    estatisticamente só com dezenas de milhares de tentativas; aqui a
#    amostra é reduzida (2000 * FBC_ESCALA) pra rodar em bash.

AtaqueColisaoChecksum() {
    ATQ_NOME="Colisão no checksum (paradoxo do aniversário)"

    local amostras=$(( 2000 * FBC_ESCALA ))

    # chave conhecida de propósito - ver comentário acima
    local -a chave_mac=()
    local i
    for (( i = 0; i < 32; i++ )); do
        chave_mac+=(77)
    done
    local chave_mac_str="${chave_mac[*]}"

    local -A vistos_completo=()
    local -A vistos_truncado=()
    local colisao_completa=0 colisao_truncada=0

    for (( i = 0; i < amostras; i++ )); do
        local -a mensagem
        util_random_bytes mensagem 20

        local -a hash
        alvo_checksum_bruto hash "${mensagem[*]}" "$chave_mac_str"

        local hash_str="${hash[*]}"

        if [ "$colisao_completa" -eq 0 ]; then
            if [ -n "${vistos_completo[$hash_str]+x}" ]; then
                colisao_completa=1
            else
                vistos_completo[$hash_str]="${mensagem[*]}"
            fi
        fi

        if [ "$colisao_truncada" -eq 0 ]; then
            local trunc_str="${hash[0]} ${hash[1]} ${hash[2]} ${hash[3]}"
            if [ -n "${vistos_truncado[$trunc_str]+x}" ]; then
                colisao_truncada=1
            else
                vistos_truncado[$trunc_str]="${mensagem[*]}"
            fi
        fi

        if [ "$colisao_completa" -eq 1 ] && [ "$colisao_truncada" -eq 1 ]; then
            break
        fi
    done

    # Colisão no checksum COMPLETO com essa amostra pequena seria uma falha
    # estrutural séria (a probabilidade por acaso é desprezível).
    if [ "$colisao_completa" -eq 1 ]; then
        res_vulneravel "COLISÃO COMPLETA encontrada em ${#vistos_completo[@]} amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente." critica
        return 0
    fi

    # Colisão truncada (32 bits) é esperada estatisticamente - não é
    # "vulnerabilidade", é confirmação de que 4 bytes isolados têm a força
    # que deveriam ter (nem mais, nem menos).
    local info_truncada
    if [ "$colisao_truncada" -eq 1 ]; then
        info_truncada="colisão de 32 bits encontrada em ${#vistos_truncado[@]} amostras (esperado pelo paradoxo do aniversário)"
    else
        info_truncada="nenhuma colisão de 32 bits em ${#vistos_truncado[@]} amostras (um pouco abaixo do esperado, mas não conclusivo)"
    fi

    res_resistiu "Nenhuma colisão completa em $amostras amostras (esperado). Nível truncado (32 bits): $info_truncada."
    return 0
}
