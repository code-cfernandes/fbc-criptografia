"""
O AtaqueIdaEVolta usa só o caractere 'Q'. Esse usa dados binários de
verdade: todos os 256 valores de byte, NUL, sequências aleatórias de vários
tamanhos. Erros de manipulação de string (trim, encoding, NUL truncation) só
aparecem com bytes arbitrários.
"""
struct AtaqueIdaEVoltaBinario <: Ataque
    tamanho_maximo::Int
end

AtaqueIdaEVoltaBinario(; tamanho_maximo::Integer = 256) =
    AtaqueIdaEVoltaBinario(Int(tamanho_maximo))

nome(::AtaqueIdaEVoltaBinario) = "Ida-e-volta com dados binários (inclui NUL)"

function executar(a::AtaqueIdaEVoltaBinario, alvo::AlvoCriptografico)
    falhas = Any[]

    for len in 0:(a.tamanho_maximo)
        bytes = len == 0 ? UInt8[] : random_bytes(len)
        texto = String(bytes)
        try
            if decrypt(alvo, encrypt(alvo, texto)) != texto
                push!(falhas, len)
            end
        catch e
            push!(falhas, "$len (erro: $(sprint(showerror, e)))")
        end
    end

    todos_bytes = UInt8[UInt8(i) for i in 0:255]
    todos = String(todos_bytes)
    try
        if decrypt(alvo, encrypt(alvo, todos)) != todos
            push!(falhas, "todos os 256 valores de byte")
        end
    catch e
        push!(falhas, "todos os 256 valores de byte (erro: $(sprint(showerror, e)))")
    end

    if !isempty(falhas)
        amostra = join(string.(falhas[1:min(10, length(falhas))]), ", ")
        return ResultadoAtaque(
            nome(a),
            true,
            "critica",
            "Falhou em $(length(falhas)) caso(s): $amostra",
            Dict{String,Any}("falhas" => falhas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "Todos os tamanhos 0..$(a.tamanho_maximo) e os 256 valores de byte preservados",
    )
end
