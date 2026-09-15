"""
Procura colisões no checksum() via paradoxo do aniversário: gera muitas
mensagens aleatórias com a MESMA chave de MAC (a chave é conhecida de
propósito aqui - testar resistência a colisão é uma propriedade do
ALGORITMO, independente de a chave ser secreta ou não; é assim que se
testa qualquer função de hash/MAC na prática).

Testa dois níveis:
1. Colisão no checksum COMPLETO (32 bytes / 256 bits) - não deveria
   aparecer nunca com uma amostra viável de testar (precisaria de ~2^128
   tentativas pelo paradoxo do aniversário).
2. Colisão nos primeiros 4 bytes (32 bits) de saída - essa É esperada
   estatisticamente com poucas dezenas de milhares de tentativas (o
   paradoxo do aniversário pra 32 bits precisa de só ~77.000 amostras
   pra 50% de chance). Isso não quebra o MAC completo (que depende dos
   32 bytes inteiros), mas mede a força de UMA rodada interna isolada -
   útil pra saber se a composição das rodadas está de fato preservando
   a força total, ou se há alguma correlação entre elas.
"""
struct AtaqueColisaoChecksum <: Ataque
    amostras::Int
end

AtaqueColisaoChecksum(; amostras::Integer = 200000) =
    AtaqueColisaoChecksum(Int(amostras))

nome(::AtaqueColisaoChecksum) = "Colisão no checksum (paradoxo do aniversário)"

function executar(a::AtaqueColisaoChecksum, alvo::AlvoCriptografico)
    chave_de_mac = repeat("M", 32) # chave conhecida de propósito - ver docblock

    primeiro = checksum_bruto(alvo, "teste", chave_de_mac)
    if primeiro === nothing
        throw(SkipAtaqueException("Alvo não expõe checksumBruto."))
    end

    vistos_completo = Dict{String,Vector{UInt8}}()
    vistos_truncado = Dict{String,Vector{UInt8}}()
    colisao_completa = nothing
    colisao_truncada = nothing

    for _ in 1:(a.amostras)
        mensagem = random_bytes(20)
        hash = checksum_bruto(alvo, mensagem, chave_de_mac)

        if colisao_completa === nothing
            chave_hash = bytes2hex(hash)
            anterior = get(vistos_completo, chave_hash, nothing)
            if anterior !== nothing
                colisao_completa = (anterior, mensagem)
            else
                vistos_completo[chave_hash] = mensagem
            end
        end

        if colisao_truncada === nothing
            truncado = bytes2hex(hash[1:4])
            anterior = get(vistos_truncado, truncado, nothing)
            if anterior !== nothing
                colisao_truncada = (anterior, mensagem)
            else
                vistos_truncado[truncado] = mensagem
            end
        end

        if colisao_completa !== nothing && colisao_truncada !== nothing
            break
        end
    end

    # Colisão no checksum COMPLETO com essa amostra pequena seria uma
    # falha estrutural séria (a probabilidade por acaso é desprezível).
    if colisao_completa !== nothing
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "COLISÃO COMPLETA encontrada em $(length(vistos_completo)) amostras - isso não deveria acontecer por acaso. Investigar o algoritmo imediatamente.",
            Dict{String,Any}(
                "msg1_hex" => bytes2hex(colisao_completa[1]),
                "msg2_hex" => bytes2hex(colisao_completa[2]),
            ),
        )
    end

    # Colisão truncada (32 bits) é esperada estatisticamente - não é
    # "vulnerabilidade", é confirmação de que 4 bytes isolados têm a
    # força que deveriam ter (nem mais, nem menos).
    info_truncada = if colisao_truncada !== nothing
        "colisão de 32 bits encontrada em $(length(vistos_truncado)) amostras (esperado pelo paradoxo do aniversário)"
    else
        "nenhuma colisão de 32 bits em $(length(vistos_truncado)) amostras (um pouco abaixo do esperado, mas não conclusivo)"
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Nenhuma colisão completa em $(a.amostras) amostras (esperado). Nível truncado (32 bits): $info_truncada.",
        Dict{String,Any}(
            "amostras_completo" => length(vistos_completo),
            "amostras_truncado" => length(vistos_truncado),
        ),
    )
end
