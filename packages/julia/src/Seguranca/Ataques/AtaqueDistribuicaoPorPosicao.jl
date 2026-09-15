"""
O AtaqueDistribuicaoBytes faz qui-quadrado GLOBAL. Esse faz POR POSIÇÃO do
bloco de 32 bytes: uma posição específica pode ter viés forte mesmo que a
soma global pareça uniforme (o viés de uma posição se dilui entre as 32).
"""
struct AtaqueDistribuicaoPorPosicao <: Ataque
    amostras_de_blocos::Int
    tamanho_bloco::Int
end

AtaqueDistribuicaoPorPosicao(;
    amostras_de_blocos::Integer = 2000,
    tamanho_bloco::Integer = 32,
) = AtaqueDistribuicaoPorPosicao(Int(amostras_de_blocos), Int(tamanho_bloco))

nome(::AtaqueDistribuicaoPorPosicao) = "Distribuição de bytes por posição do bloco"

function executar(a::AtaqueDistribuicaoPorPosicao, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)

    contagens = [zeros(Int, 256) for _ in 1:(a.tamanho_bloco)]

    for _ in 1:(a.amostras_de_blocos)
        ks = gerar_keystream_bruto(
            alvo,
            chave,
            random_bytes(tamanho_iv(alvo)),
            "enc",
            a.tamanho_bloco,
        )
        for p in 0:(a.tamanho_bloco-1)
            contagens[p+1][ks[p+1]+1] += 1
        end
    end

    esperado = a.amostras_de_blocos / 256
    problemas = String[]
    pior = 0.0

    for p in 1:length(contagens)
        c = contagens[p]
        chi2 = 0.0
        for v in c
            chi2 += (v - esperado)^2 / esperado
        end
        pior = max(pior, chi2)
        z = (chi2 - 255) / sqrt(510)
        if z > 4.0
            push!(problemas, "posição $(p-1) chi2=$(fmt(chi2, 1))")
        end
    end

    if !isempty(problemas)
        return ResultadoAtaque(nome(a), true, "media", join(problemas, "; "))
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todas as $(a.tamanho_bloco) posições uniformes (pior chi2=$(fmt(pior, 1)), esperado ~255)",
    )
end
