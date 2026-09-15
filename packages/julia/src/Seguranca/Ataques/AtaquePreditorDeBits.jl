"""
Previsibilidade: treina um preditor por contexto (os k bits anteriores) na
primeira metade do keystream e mede a taxa de acerto na segunda metade. Para
um gerador sem memória/correlação local, a taxa fica em ~50% (chute).
Qualquer coisa acima disso indica que os bits carregam dependência explorável
- o embrião de um ataque de predição de estado.
"""
struct AtaquePreditorDeBits <: Ataque
    tamanho::Int
    contexto::Int
    limite_taxa::Float64
end

AtaquePreditorDeBits(;
    tamanho::Integer = 16384,
    contexto::Integer = 8,
    limite_taxa::Real = 0.55,
) = AtaquePreditorDeBits(Int(tamanho), Int(contexto), Float64(limite_taxa))

nome(::AtaquePreditorDeBits) = "Previsibilidade de bits (preditor por contexto)"

function _preditor_contexto(bits::AbstractVector{<:Integer}, i0::Integer, k::Integer)
    ctx = 0
    for j in (i0-k):(i0-1)
        ctx = (ctx << 1) | bits[j+1]
    end
    return ctx
end

function executar(a::AtaquePreditorDeBits, alvo::AlvoCriptografico)
    ks = gerar_keystream_bruto(
        alvo,
        chave_de_teste(alvo),
        random_bytes(tamanho_iv(alvo)),
        "enc",
        a.tamanho,
    )

    bits = bits_msb(ks)
    n = length(bits)
    k = a.contexto
    total = 1 << k
    metade = div(n, 2)

    uns = zeros(Int, total)
    cont = zeros(Int, total)
    for i in k:(metade-1)
        ctx = _preditor_contexto(bits, i, k)
        uns[ctx+1] += bits[i+1]
        cont[ctx+1] += 1
    end

    acertos = 0
    testes = 0
    for i in metade:(n-1)
        ctx = _preditor_contexto(bits, i, k)
        if cont[ctx+1] == 0
            continue
        end
        predicao = uns[ctx+1] * 2 > cont[ctx+1] ? 1 : 0
        if predicao == bits[i+1]
            acertos += 1
        end
        testes += 1
    end

    taxa = testes > 0 ? acertos / testes : 0.5
    vulneravel = taxa > a.limite_taxa

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "taxa de acerto=$(fmt(taxa * 100, 2))% com contexto de $k bits (esperado ~50%, limite=$(fmt(a.limite_taxa * 100, 0))%) sobre $testes testes",
        Dict{String,Any}("taxa" => taxa, "testes" => testes),
    )
end
