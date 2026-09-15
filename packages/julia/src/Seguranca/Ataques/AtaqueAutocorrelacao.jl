"""
O AtaqueFoldEstrutural olha repetição DENTRO de um bloco de 32 bytes.
Esse olha o keystream LONGO: correlação serial entre bytes vizinhos,
autocorrelação em lags (inclusive múltiplos do bloco, pra pegar reset de
estado), blocos de 32 bytes repetidos e o balanço global de bits. Um
keystream aleatório deve ter todos esses indicadores perto de zero/50%.
"""
struct AtaqueAutocorrelacao <: Ataque
    tamanho::Int
    tamanho_bloco::Int
end

AtaqueAutocorrelacao(; tamanho::Integer = 8192, tamanho_bloco::Integer = 32) =
    AtaqueAutocorrelacao(Int(tamanho), Int(tamanho_bloco))

nome(::AtaqueAutocorrelacao) = "Autocorrelação e periodicidade do keystream"

function _correlacao_serial(s::AbstractVector{UInt8}, lag::Integer)
    n = length(s)
    if n <= lag
        return 0.0
    end

    media = sum(Int, s) / n

    den = 0.0
    for i in 1:n
        den += (s[i] - media)^2
    end
    num = 0.0
    for i in 1:(n-lag)
        num += (s[i] - media) * (s[i+lag] - media)
    end

    return den > 0 ? num / den : 0.0
end

function executar(a::AtaqueAutocorrelacao, alvo::AlvoCriptografico)
    ks = gerar_keystream_bruto(
        alvo,
        chave_de_teste(alvo),
        random_bytes(tamanho_iv(alvo)),
        "enc",
        a.tamanho,
    )

    serial = _correlacao_serial(ks, 1)

    suspeitos = Dict{Int,Float64}()
    for lag in [2, 4, 8, 16, 32, 64, 128, 256]
        c = _correlacao_serial(ks, lag)
        if abs(c) > 0.1
            suspeitos[lag] = c
        end
    end

    blocos = String[]
    for i in 0:(a.tamanho_bloco):(length(ks)-1)
        fim = min(i + a.tamanho_bloco, length(ks))
        push!(blocos, bytes2hex(ks[i+1:fim]))
    end
    blocos_unicos = Set(blocos)
    blocos_repetidos = length(blocos) - length(blocos_unicos)

    uns = contar_bits_buffer(ks)
    fracao_uns = uns / (length(ks) * 8)

    problemas = String[]
    if abs(serial) > 0.1
        push!(problemas, "correlação serial=$(fmt(serial, 3))")
    end
    if !isempty(suspeitos)
        push!(
            problemas,
            "autocorrelação em lag(s) " * join(sort(collect(keys(suspeitos))), ", "),
        )
    end
    if blocos_repetidos > 0
        push!(problemas, "$blocos_repetidos bloco(s) de $(a.tamanho_bloco) bytes repetido(s)")
    end
    if fracao_uns < 0.45 || fracao_uns > 0.55
        push!(problemas, "balanço de bits=$(fmt(fracao_uns * 100, 1))% de 1s")
    end

    if !isempty(problemas)
        return ResultadoAtaque(nome(a), true, "media", join(problemas, "; "))
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "serial=$(fmt(serial, 3)), nenhum lag com correlação >10%, 0 blocos repetidos em $(length(blocos)), $(fmt(fracao_uns * 100, 1))% de bits 1",
    )
end
