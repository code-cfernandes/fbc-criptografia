"""
Cifras às vezes têm "chaves fracas" ou "IVs fracos" - entradas específicas
(tudo zero, tudo 0xFF, padrões alternados) que produzem saída degenerada mesmo
quando a maioria das entradas se comporta bem. Testa especificamente esses
casos extremos, que testes com entrada aleatória raramente cobrem.
"""
struct AtaqueIVsDegenerados <: Ataque end

nome(::AtaqueIVsDegenerados) = "IVs degenerados (zero, 0xFF, alternado)"

function executar(a::AtaqueIVsDegenerados, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)
    tam_iv = tamanho_iv(alvo)
    tamanho_bloco = 32

    crescente = UInt8[UInt8(i) for i in 0:(tam_iv-1)]

    casos = Pair{String,Vector{UInt8}}[
        "zero" => zeros(UInt8, tam_iv),
        "0xFF" => fill(0xff, tam_iv),
        "alternado 0xAA" => fill(0xaa, tam_iv),
        "alternado 0x55" => fill(0x55, tam_iv),
        "crescente" => crescente,
    ]

    problemas = Dict{String,Any}()
    for (nome_caso, iv) in casos
        ks = gerar_keystream_bruto(alvo, chave, iv, "enc", tamanho_bloco)

        metade = div(tamanho_bloco, 2)
        periodico = ks[1:metade] == ks[metade+1:2*metade]

        bytes_unicos = length(Set(ks))
        if periodico || bytes_unicos < tamanho_bloco * 0.5
            problemas[nome_caso] = (periodico=periodico, bytes_unicos=bytes_unicos)
        end
    end

    if !isempty(problemas)
        detalhe = join(
            [
                "$(nome_caso) (periódico=$(problemas[nome_caso].periodico ? "sim" : "não"), bytes únicos=$(problemas[nome_caso].bytes_unicos)/$tamanho_bloco)"
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
        "Nenhum dos $(length(casos)) IVs degenerados testados produziu saída anômala",
    )
end
