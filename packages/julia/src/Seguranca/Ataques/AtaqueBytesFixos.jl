"""
Versões antigas dessa cifra tinham um header fixo ou um marcador constante. Esse
ataque gera vários tokens de textos diferentes e procura qualquer posição de
byte que NUNCA muda — uma âncora que um atacante pode usar pra recuperar a chave.
"""
struct AtaqueBytesFixos <: Ataque
    amostras::Int
end

AtaqueBytesFixos(; amostras::Integer = 30) = AtaqueBytesFixos(Int(amostras))

nome(::AtaqueBytesFixos) = "Bytes fixos entre tokens"

function executar(a::AtaqueBytesFixos, alvo::AlvoCriptografico)
    tokens = String[]
    for i in 0:(a.amostras-1)
        letra = string(Char(65 + mod(i, 26)))
        texto = "TEXTO_VARIADO_$i" * repeat(letra, mod(i, 10))
        push!(tokens, encrypt(alvo, texto)[4:end])
    end

    decodificados = [base64url_decode(alvo, t) for t in tokens]
    tamanho_minimo = minimum(length.(decodificados))

    posicoes_fixas = Int[]
    for i in 1:tamanho_minimo
        valores = Set(d[i] for d in decodificados)
        if length(valores) == 1
            push!(posicoes_fixas, i - 1)
        end
    end

    if !isempty(posicoes_fixas)
        return ResultadoAtaque(
            nome(a),
            true,
            "alta",
            "$(length(posicoes_fixas)) posição(ões) de byte fixas em $(a.amostras) tokens: " *
            join(posicoes_fixas[1:min(10, length(posicoes_fixas))], ", "),
            Dict{String,Any}("posicoes" => posicoes_fixas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "0 de $tamanho_minimo posições fixas em $(a.amostras) tokens",
    )
end
