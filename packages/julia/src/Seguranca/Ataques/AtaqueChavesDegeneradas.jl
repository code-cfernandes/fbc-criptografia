"""
Análogo ao AtaqueIVsDegenerados, mas para a CHAVE. Chaves especiais
(tudo zero, tudo 0xFF, padrões alternados, baixa entropia) não podem
produzir keystream degenerado - e aqui testamos no pior cenário, com IV
zerado junto, pra isolar a contribuição da chave.
"""
struct AtaqueChavesDegeneradas <: Ataque
    tamanho_bloco::Int
end

AtaqueChavesDegeneradas(; tamanho_bloco::Integer = 32) =
    AtaqueChavesDegeneradas(Int(tamanho_bloco))

nome(::AtaqueChavesDegeneradas) =
    "Chaves degeneradas (zero, 0xFF, alternada, baixa entropia)"

function executar(a::AtaqueChavesDegeneradas, alvo::AlvoCriptografico)
    tam_chave = length(codeunits(chave_de_teste(alvo)))
    iv_zero = zeros(UInt8, tamanho_iv(alvo))

    seq_crescente = UInt8[UInt8(i % 256) for i in 0:511]

    casos = Pair{String,Vector{UInt8}}[
        "zero" => zeros(UInt8, tam_chave),
        "0xFF" => fill(0xff, tam_chave),
        "alternada 0xAA" => fill(0xaa, tam_chave),
        "alternada 0x55" => fill(0x55, tam_chave),
        "repetida \"A\"" => fill(0x41, tam_chave),
        "crescente" => seq_crescente[1:tam_chave],
    ]

    problemas = Dict{String,Any}()
    for (nome_caso, chave) in casos
        ks = gerar_keystream_bruto(alvo, chave, iv_zero, "enc", a.tamanho_bloco)

        metade = div(a.tamanho_bloco, 2)
        periodico = ks[1:metade] == ks[metade+1:2*metade]
        bytes_unicos = length(Set(ks))

        if periodico || bytes_unicos < a.tamanho_bloco * 0.5
            problemas[nome_caso] = (periodico=periodico, bytes_unicos=bytes_unicos)
        end
    end

    if !isempty(problemas)
        detalhe = join(
            [
                "$(nome_caso) (periódico=$(problemas[nome_caso].periodico ? "sim" : "não"), bytes únicos=$(problemas[nome_caso].bytes_unicos)/$(a.tamanho_bloco))"
                for (nome_caso, _) in casos if haskey(problemas, nome_caso)
            ],
            "; ",
        )
        return ResultadoAtaque(nome(a), true, "alta", detalhe, problemas)
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Nenhuma das $(length(casos)) chaves degeneradas testadas produziu saída anômala",
    )
end
