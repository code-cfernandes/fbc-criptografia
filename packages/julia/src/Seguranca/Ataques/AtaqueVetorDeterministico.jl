"""
Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico.
Também imprime o vetor de referência (KAT) para esse par key/iv.
"""
struct AtaqueVetorDeterministico <: Ataque end

nome(::AtaqueVetorDeterministico) = "Determinismo (vetor de referência key/iv fixos)"

function executar(a::AtaqueVetorDeterministico, alvo::AlvoCriptografico)
    chave_fixa = repeat("K", length(codeunits(chave_de_teste(alvo))))
    iv_fixo = zeros(UInt8, tamanho_iv(alvo))

    ks1 = gerar_keystream_bruto(alvo, chave_fixa, iv_fixo, "enc", 32)
    ks2 = gerar_keystream_bruto(alvo, chave_fixa, iv_fixo, "enc", 32)
    ks3 = gerar_keystream_bruto(alvo, chave_fixa, iv_fixo, "enc", 32)

    deterministico = ks1 == ks2 && ks2 == ks3
    hex1 = bytes2hex(ks1)

    detalhes = deterministico ?
               "Determinístico em 3 chamadas. Vetor de referência (key=64x\"K\", iv=zeros, prop=enc, 32 bytes): " *
               hex1 :
               "NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: " *
               hex1 * " / " * bytes2hex(ks2) * " / " * bytes2hex(ks3)

    return ResultadoAtaque(
        nome(a),
        !deterministico,
        deterministico ? "info" : "critica",
        detalhes,
        Dict{String,Any}("vetor_hex" => hex1),
    )
end
