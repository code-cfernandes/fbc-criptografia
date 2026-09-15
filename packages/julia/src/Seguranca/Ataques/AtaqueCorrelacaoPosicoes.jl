"""
Verifica se posições DIFERENTES dentro do mesmo bloco de 32 bytes saem
correlacionadas (ex: posição 0 acompanha posição 16). Uma correlação entre
posições de saída é exatamente o tipo de estrutura que o antigo bug da
"metade igual" produzia - e que a autocorrelação temporal pode não pegar.
"""
struct AtaqueCorrelacaoPosicoes <: Ataque
    amostras::Int
    tamanho_bloco::Int
    limite_correlacao::Float64
end

AtaqueCorrelacaoPosicoes(;
    amostras::Integer = 3000,
    tamanho_bloco::Integer = 32,
    limite_correlacao::Real = 0.15,
) = AtaqueCorrelacaoPosicoes(
    Int(amostras),
    Int(tamanho_bloco),
    Float64(limite_correlacao),
)

nome(::AtaqueCorrelacaoPosicoes) = "Correlação entre posições do bloco"

function _pearson_posicoes(blocos::AbstractVector, a::Integer, b::Integer)
    n = length(blocos)
    ma = 0.0
    mb = 0.0
    for d in blocos
        ma += d[a+1]
        mb += d[b+1]
    end
    ma /= n
    mb /= n

    num = 0.0
    da = 0.0
    db = 0.0
    for d in blocos
        xa = d[a+1] - ma
        xb = d[b+1] - mb
        num += xa * xb
        da += xa * xa
        db += xb * xb
    end

    return da > 0 && db > 0 ? num / sqrt(da * db) : 0.0
end

function executar(a::AtaqueCorrelacaoPosicoes, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)

    blocos = Vector{UInt8}[]
    for _ in 1:(a.amostras)
        push!(
            blocos,
            gerar_keystream_bruto(
                alvo,
                chave,
                random_bytes(tamanho_iv(alvo)),
                "enc",
                a.tamanho_bloco,
            ),
        )
    end

    suspeitos = String[]
    pior = 0.0

    for a_pos in 0:(a.tamanho_bloco-1)
        for b_pos in (a_pos+1):(a.tamanho_bloco-1)
            corr = _pearson_posicoes(blocos, a_pos, b_pos)
            if abs(corr) > abs(pior)
                pior = corr
            end
            if abs(corr) > a.limite_correlacao
                push!(suspeitos, "posições $a_pos-$b_pos (r=$(fmt(corr, 3)))")
            end
        end
    end

    if !isempty(suspeitos)
        return ResultadoAtaque(
            nome(a),
            true,
            "alta",
            "$(length(suspeitos)) par(es) correlacionado(s): $(join(suspeitos[1:min(10, length(suspeitos))], "; "))",
            Dict{String,Any}("suspeitos" => suspeitos),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Nenhum par de posições correlacionado acima de $(fmt(a.limite_correlacao, 2)) (pior |r|=$(fmt(abs(pior), 3)))",
    )
end
