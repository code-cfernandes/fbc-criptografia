"""
Somas cumulativas (cusum), teste do NIST SP800-22. Converte os bits em
passos +1/-1 e observa o maior desvio da caminhada aleatória. Um viés
pequeno que o monobit quase não vê faz o desvio acumulado crescer.
Para uma sequência aleatória, max|S|/sqrt(n) fica tipicamente abaixo de 3.
"""
struct AtaqueCusum <: Ataque
    tamanho::Int
    limite_z::Float64
end

AtaqueCusum(; tamanho::Integer = 8192, limite_z::Real = 4.0) =
    AtaqueCusum(Int(tamanho), Float64(limite_z))

nome(::AtaqueCusum) = "Somas cumulativas (cusum)"

function executar(a::AtaqueCusum, alvo::AlvoCriptografico)
    ks = gerar_keystream_bruto(
        alvo,
        chave_de_teste(alvo),
        random_bytes(tamanho_iv(alvo)),
        "enc",
        a.tamanho,
    )

    soma = 0
    max_abs = 0
    for byte in ks
        for b in 7:-1:0
            soma += ((byte >> b) & 1) == 1 ? 1 : -1
            max_abs = max(max_abs, abs(soma))
        end
    end
    n = length(ks) * 8
    z = max_abs / sqrt(n)
    vulneravel = z > a.limite_z

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        "max|S|=$max_abs sobre $n bits, max|S|/sqrt(n)=$(fmt(z, 2)) (limite=$(fmt(a.limite_z, 1)))",
        Dict{String,Any}("max_abs" => max_abs, "z" => z),
    )
end
