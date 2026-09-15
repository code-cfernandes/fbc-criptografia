# O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
# interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
# dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
# posição específica significa que aquele byte quase não influencia o MAC -
# uma pista forte de que a mistura tem um "ponto cego" estrutural.
#
# Varre TODAS as posições/bits da entrada (não amostra aleatória) para
# apontar exatamente onde está o ponto fraco.
AtaqueAvalancheChecksum() {
    ATQ_NOME="Efeito avalanche do checksum/MAC"

    # Reduzido: mensagensPorCombinacao ~2 e tamanhoEntrada ~8 (era 10 e 32).
    local mensagens=$(( 2 * FBC_ESCALA ))
    local tamanho_entrada=8
    local limite_media=0.40
    local limite_pior_caso=0.40

    local -a chave_mac=()
    local i
    for (( i = 0; i < 32; i++ )); do
        chave_mac+=(77)
    done
    local chave_mac_str="${chave_mac[*]}"

    local -a teste_bytes=()
    string_to_bytes teste_bytes "teste"
    local -a primeiro=()
    alvo_checksum_bruto primeiro "${teste_bytes[*]}" "$chave_mac_str"
    if [ ${#primeiro[@]} -eq 0 ]; then
        res_skip "Alvo não expõe checksum_bruto."
        return 0
    fi
    local tamanho_saida=${#primeiro[@]}

    local total_bits=0 total_msgs=0 combinacoes=0
    local pior_valor=1.0 pior_pos=-1 pior_bit=-1
    local pos bit m
    for (( pos = 0; pos < tamanho_entrada; pos++ )); do
        for (( bit = 0; bit < 8; bit++ )); do
            local soma_bits=0
            for (( m = 0; m < mensagens; m++ )); do
                local -a entrada=()
                local -a alterada=()
                util_random_bytes entrada "$tamanho_entrada"
                alterada=("${entrada[@]}")
                alterada[pos]=$(( alterada[pos] ^ (1 << bit) ))

                local -a h1=()
                local -a h2=()
                alvo_checksum_bruto h1 "${entrada[*]}" "$chave_mac_str"
                alvo_checksum_bruto h2 "${alterada[*]}" "$chave_mac_str"

                local diff
                diff=$(util_bits_diferentes "${h1[*]}" "${h2[*]}")
                soma_bits=$(( soma_bits + diff ))
            done

            local media
            media=$(util_div "$soma_bits" $(( mensagens * tamanho_saida * 8 )) 10)
            total_bits=$(( total_bits + soma_bits ))
            total_msgs=$(( total_msgs + mensagens ))
            combinacoes=$(( combinacoes + 1 ))
            if util_menor "$media" "$pior_valor"; then
                pior_valor=$media
                pior_pos=$pos
                pior_bit=$bit
            fi
        done
    done

    local media_global
    media_global=$(util_div "$total_bits" $(( total_msgs * tamanho_saida * 8 )) 10)

    local vulneravel=0
    if util_menor "$media_global" "$limite_media" || util_menor "$pior_valor" "$limite_pior_caso"; then
        vulneravel=1
    fi

    local severidade="info"
    if [ "$vulneravel" -eq 1 ]; then
        if util_menor "$pior_valor" 0.30; then
            severidade="alta"
        else
            severidade="media"
        fi
    fi

    local detalhes
    detalhes="média global=$(util_pct "$media_global" 1 1)%; pior caso=$(util_pct "$pior_valor" 1 1)% na entrada[posição=$pior_pos, bit=$pior_bit] sobre $tamanho_saida bytes de MAC (limites: média>=$(util_pct "$limite_media" 1 0)%, pior>=$(util_pct "$limite_pior_caso" 1 0)%)"

    if [ "$vulneravel" -eq 1 ]; then
        res_vulneravel "$detalhes" "$severidade"
    else
        res_resistiu "$detalhes" "info"
    fi
    return 0
}
