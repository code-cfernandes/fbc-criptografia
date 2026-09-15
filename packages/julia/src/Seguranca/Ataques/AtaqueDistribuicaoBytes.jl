"""
Um keystream de qualidade deve ter bytes distribuídos uniformemente entre
0-255. Um viés forte (qui-quadrado muito alto) indica que alguns valores
de byte saem com mais frequência que outros - sinal de fraqueza estatística
na função de mistura.
"""
struct AtaqueDistribuicaoBytes <: Ataque
    amostras_de_blocos::Int
    tamanho_bloco::Int
end

AtaqueDistribuicaoBytes(;
    amostras_de_blocos::Integer = 500,
    tamanho_bloco::Integer = 32,
) = AtaqueDistribuicaoBytes(Int(amostras_de_blocos), Int(tamanho_bloco))

nome(::AtaqueDistribuicaoBytes) = "Distribuição de bytes (qui-quadrado)"

function executar(a::AtaqueDistribuicaoBytes, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)

    contagem = zeros(Int, 256)
    total = 0
    for _ in 1:(a.amostras_de_blocos)
        ks = gerar_keystream_bruto(
            alvo,
            chave,
            random_bytes(tamanho_iv(alvo)),
            "enc",
            a.tamanho_bloco,
        )
        for byte in ks
            contagem[byte+1] += 1
            total += 1
        end
    end

    esperado = total / 256
    qui2 = 0.0
    for c in contagem
        qui2 += (c - esperado)^2 / esperado
    end

    # Com 255 graus de liberdade, valores acima de ~330 já são
    # estatisticamente suspeitos (p < 0.01); acima de ~380, bem suspeitos.
    vulneravel = qui2 > 330

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        "qui-quadrado=$(fmt(qui2, 1)) sobre $total bytes (255 graus de liberdade; >330 é suspeito)",
        Dict{String,Any}("qui2" => qui2),
    )
end
