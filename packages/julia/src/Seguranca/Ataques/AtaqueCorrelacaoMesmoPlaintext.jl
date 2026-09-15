"""
O AtaqueColisaoIV já garante que o MESMO plaintext nunca reusa o IV.
Esse ataque vai além: verifica se os CIPHERTEXTS resultantes, embora
venham do mesmo texto, se comportam como se fossem de textos diferentes
(distância de Hamming média ~50%, sem nenhum padrão fixo entre eles).

Se o IV está fazendo seu trabalho, cifrar "SEGREDO" 500 vezes deveria
parecer, aos olhos de quem só vê o ciphertext, tão aleatório quanto
cifrar 500 textos diferentes.
"""
struct AtaqueCorrelacaoMesmoPlaintext <: Ataque
    amostras::Int
    texto_fixo::String
end

AtaqueCorrelacaoMesmoPlaintext(;
    amostras::Integer = 300,
    texto_fixo::AbstractString = "MENSAGEM_SEMPRE_IGUAL_PARA_TESTAR",
) = AtaqueCorrelacaoMesmoPlaintext(Int(amostras), String(texto_fixo))

nome(::AtaqueCorrelacaoMesmoPlaintext) = "Correlação entre ciphertexts do mesmo plaintext"

function _distancia_hamming_relativa(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})
    len = min(length(a), length(b))
    if len == 0
        return 0.5
    end
    diff = 0
    for i in 1:len
        diff += contar_bits1(a[i] ⊻ b[i])
    end
    return diff / (len * 8)
end

function executar(a::AtaqueCorrelacaoMesmoPlaintext, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_decode do alvo."))
    end

    ciphertexts = Vector{UInt8}[]
    for _ in 1:(a.amostras)
        token = encrypt(alvo, a.texto_fixo)
        decodificado = base64url_decode(alvo, token[length(prefixo(alvo))+1:end])
        push!(ciphertexts, decompor(alvo, decodificado).ciphertext)
    end

    # Compara pares aleatórios de ciphertexts (não todos contra todos,
    # pra manter o custo baixo) e mede a distância de Hamming média.
    comparacoes = min(500, trunc(Int, (a.amostras * (a.amostras - 1)) / 2))
    distancias = Float64[]
    for _ in 1:comparacoes
        i = random_int(0, a.amostras - 1)
        j = random_int(0, a.amostras - 1)
        if i == j
            continue
        end
        push!(distancias, _distancia_hamming_relativa(ciphertexts[i+1], ciphertexts[j+1]))
    end

    media = sum(distancias) / length(distancias)

    # Também confere que nenhum PAR de ciphertexts é idêntico (o que
    # indicaria reuso de IV+key, capturado de outro ângulo).
    unicos = Set(bytes2hex(c) for c in ciphertexts)
    duplicatas = a.amostras - length(unicos)

    vulneravel = media < 0.4 || media > 0.6 || duplicatas > 0

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "alta" : "info",
        "distância de Hamming média entre ciphertexts do mesmo texto: $(fmt(media * 100, 1))% (esperado ~50%), $duplicatas duplicata(s) exata(s) em $(a.amostras) amostras",
        Dict{String,Any}("media" => media, "duplicatas" => duplicatas),
    )
end
