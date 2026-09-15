"""
Aproximação linear (criptoanálise de Matsui): procura por correlação entre bits
de entrada (IV) e bits de saída do keystream. Uma cifra ideal não tem
aproximação linear com viés relevante; bias alto é uma pista explorável.
"""
struct AtaqueAproximacaoLinear <: Ataque
    amostras::Int
    tamanho_bloco::Int
    limite_bias::Float64
end

AtaqueAproximacaoLinear(;
    amostras::Integer = 200,
    tamanho_bloco::Integer = 32,
    limite_bias::Real = 0.3,
) = AtaqueAproximacaoLinear(Int(amostras), Int(tamanho_bloco), Float64(limite_bias))

nome(::AtaqueAproximacaoLinear) = "Aproximação linear (viés de Walsh)"

function executar(a::AtaqueAproximacaoLinear, alvo::AlvoCriptografico)
    tam_iv = tamanho_iv(alvo)
    bits_entrada = tam_iv * 8
    bits_saida = a.tamanho_bloco * 8
    tam_chave = length(codeunits(chave_de_teste(alvo)))

    entradas = zeros(Int, a.amostras, bits_entrada)
    saidas = zeros(Int, a.amostras, bits_saida)

    for s in 1:(a.amostras)
        chave = random_bytes(tam_chave)
        iv = random_bytes(tam_iv)
        ks = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho_bloco)

        for j in 0:(bits_entrada-1)
            entradas[s, j+1] = (iv[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
        end
        for j in 0:(bits_saida-1)
            saidas[s, j+1] = (ks[div(j, 8)+1] >> (7 - (j & 7))) & 0x01
        end
    end

    maior_bias = 0.0
    par = (-1, -1)
    for i in 0:(bits_entrada-1)
        for j in 0:(bits_saida-1)
            iguais = 0
            for s in 1:(a.amostras)
                if entradas[s, i+1] == saidas[s, j+1]
                    iguais += 1
                end
            end
            bias = abs(iguais / a.amostras - 0.5)
            if bias > maior_bias
                maior_bias = bias
                par = (i, j)
            end
        end
    end

    vulneravel = maior_bias > a.limite_bias

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "maior viés |p-0.5|=$(fmt(maior_bias, 4)) na aproximação IV[bit $(par[1])] -> saída[bit $(par[2])] (limite $(a.limite_bias)); $(a.amostras) amostras",
        Dict{String,Any}("maior_bias" => maior_bias, "par" => [par[1], par[2]]),
    )
end
