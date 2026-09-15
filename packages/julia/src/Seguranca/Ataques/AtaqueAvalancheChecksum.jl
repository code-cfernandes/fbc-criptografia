"""
O AtaqueColisaoChecksum verifica se há colisões; esse verifica a difusão
interna: mudar 1 bit da MENSAGEM autenticada deveria mudar ~50% dos bits
dos 32 bytes de MAC, em QUALQUER posição. Um efeito avalanche fraco numa
posição específica significa que aquele byte quase não influencia o MAC -
uma pista forte de que a mistura tem um "ponto cego" estrutural.

Varre TODAS as posições/bits da entrada (não amostra aleatória) para
apontar exatamente onde está o ponto fraco.
"""
struct AtaqueAvalancheChecksum <: Ataque
    mensagens_por_combinacao::Int
    tamanho_entrada::Int
    limite_media::Float64
    limite_pior_caso::Float64
end

AtaqueAvalancheChecksum(;
    mensagens_por_combinacao::Integer = 10,
    tamanho_entrada::Integer = 32,
    limite_media::Real = 0.4,
    limite_pior_caso::Real = 0.4,
) = AtaqueAvalancheChecksum(
    Int(mensagens_por_combinacao),
    Int(tamanho_entrada),
    Float64(limite_media),
    Float64(limite_pior_caso),
)

nome(::AtaqueAvalancheChecksum) = "Efeito avalanche do checksum/MAC"

function executar(a::AtaqueAvalancheChecksum, alvo::AlvoCriptografico)
    chave_mac = repeat("M", 32)

    primeiro = checksum_bruto(alvo, "teste", chave_mac)
    tamanho_saida = length(primeiro)

    soma_global = 0.0
    combinacoes = 0
    pior_posicao = -1
    pior_bit = -1
    pior_valor = 1.0

    for pos in 0:(a.tamanho_entrada-1)
        for bit in 0:7
            soma = 0.0
            for _ in 1:(a.mensagens_por_combinacao)
                entrada = random_bytes(a.tamanho_entrada)
                alterada = copy(entrada)
                alterada[pos+1] = alterada[pos+1] ⊻ UInt8(1 << bit)

                h1 = checksum_bruto(alvo, entrada, chave_mac)
                h2 = checksum_bruto(alvo, alterada, chave_mac)

                soma += bits_diferentes(h1, h2) / (tamanho_saida * 8)
            end
            media = soma / a.mensagens_por_combinacao

            soma_global += media
            combinacoes += 1
            if media < pior_valor
                pior_posicao = pos
                pior_bit = bit
                pior_valor = media
            end
        end
    end

    media_global = soma_global / combinacoes
    vulneravel = media_global < a.limite_media || pior_valor < a.limite_pior_caso

    severidade = if !vulneravel
        "info"
    elseif pior_valor < 0.3
        "alta"
    else
        "media"
    end

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        severidade,
        "média global=$(fmt(media_global * 100, 1))%; pior caso=$(fmt(pior_valor * 100, 1))% na entrada[posição=$pior_posicao, bit=$pior_bit] sobre $tamanho_saida bytes de MAC (limites: média>=$(fmt(a.limite_media * 100, 0))%, pior>=$(fmt(a.limite_pior_caso * 100, 0))%)",
        Dict{String,Any}(
            "media_global" => media_global,
            "pior" => Dict{String,Any}(
                "posicao" => pior_posicao,
                "bit" => pior_bit,
                "valor" => pior_valor,
            ),
        ),
    )
end
