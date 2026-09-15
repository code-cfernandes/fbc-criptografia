"""
Testa mensagens grandes (vários blocos de 32 bytes de keystream). Erros de
sincronização de bloco, repetição de keystream em blocos distantes ou perda
de bytes aparecem só em mensagens longas - os testes de ida-e-volta curtos
não pegam. Também confirma que o mesmo texto com IVs diferentes gera tokens
diferentes.
"""
struct AtaqueMensagemLonga <: Ataque
    tamanhos::Vector{Int}
end

AtaqueMensagemLonga(; tamanhos::Vector{<:Integer} = [1000, 10000, 100000]) =
    AtaqueMensagemLonga(Int.(tamanhos))

nome(::AtaqueMensagemLonga) = "Mensagens longas (multi-bloco)"

function executar(a::AtaqueMensagemLonga, alvo::AlvoCriptografico)
    falhas = String[]

    for t in a.tamanhos
        bytes = random_bytes(t)
        texto = String(bytes)
        try
            token = encrypt(alvo, texto)
            if decrypt(alvo, token) != texto
                push!(falhas, "$t bytes (conteúdo diferente)")
            end
        catch e
            push!(falhas, "$t bytes (erro: $(sprint(showerror, e)))")
        end
    end

    texto = repeat("A", 1000)
    t1 = encrypt(alvo, texto)
    t2 = encrypt(alvo, texto)
    if t1 == t2
        push!(falhas, "tokens idênticos para o mesmo texto (IV não varia)")
    end

    if !isempty(falhas)
        return ResultadoAtaque(nome(a), true, "critica", "Falha em: " * join(falhas, "; "))
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Ida-e-volta OK em " *
        join(a.tamanhos, ", ") *
        " bytes; mesmo texto gera tokens distintos",
    )
end
