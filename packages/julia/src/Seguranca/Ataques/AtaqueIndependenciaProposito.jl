"""
A mesma (key, iv) é usada pra derivar o keystream de dados ('enc') e a chave
do MAC ('mac'). Se os dois streams não forem independentes, um atacante que
recupere o keystream de dados (ataque de texto conhecido) pode derivar a
chave do MAC e FORJAR tokens válidos.

O teste procura dois sintomas de acoplamento:
 1. a distância de Hamming média entre os streams deve ser ~50%;
 2. XOR(enc, mac) NÃO pode se repetir entre (key, iv) diferentes - se for
    uma máscara fixa, o mac é 100% previsível a partir do enc.
"""
struct AtaqueIndependenciaProposito <: Ataque
    amostras::Int
    tamanho::Int
end

AtaqueIndependenciaProposito(; amostras::Integer = 2000, tamanho::Integer = 32) =
    AtaqueIndependenciaProposito(Int(amostras), Int(tamanho))

nome(::AtaqueIndependenciaProposito) =
    "Independência entre keystreams de propósitos diferentes (enc x mac)"

function executar(a::AtaqueIndependenciaProposito, alvo::AlvoCriptografico)
    tam_chave = length(codeunits(chave_de_teste(alvo)))

    distancias = Float64[]
    mascaras = Set{String}()

    for _ in 1:(a.amostras)
        chave = random_bytes(tam_chave)
        iv = random_bytes(tamanho_iv(alvo))

        enc = gerar_keystream_bruto(alvo, chave, iv, "enc", a.tamanho)
        mac = gerar_keystream_bruto(alvo, chave, iv, "mac", a.tamanho)

        push!(distancias, bits_diferentes(enc, mac) / (a.tamanho * 8))
        push!(mascaras, bytes2hex(xor_bytes(enc, mac)))
    end

    media = sum(distancias) / length(distancias)
    mascaras_distintas = length(mascaras)

    vulneravel = media < 0.4 || media > 0.6 || mascaras_distintas < a.amostras

    detalhe =
        "Hamming médio enc x mac=$(fmt(media * 100, 1))% (esperado ~50%); " *
        "$mascaras_distintas máscara(s) XOR distinta(s) em $(a.amostras) amostras" *
        (
            mascaras_distintas < a.amostras ?
            " - MÁSCARA REPETIDA: mac previsível a partir de enc!" : ""
        )

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        detalhe,
        Dict{String,Any}("media" => media, "mascaras_distintas" => mascaras_distintas),
    )
end
