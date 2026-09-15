"""
A encrypt() pública sempre gera um IV aleatório novo - não dá pra forçar
reuso através dela (por isso o AtaqueColisaoIV nunca encontra colisão). Esse
ataque usa o gerador de keystream de baixo nível pra SIMULAR o que aconteceria
SE o IV fosse reusado (por um bug externo, uma falha do gerador aleatório do
sistema, etc.) - e prova matematicamente o quanto vaza nesse cenário
catastrófico.

Isso não é um "bug" da implementação (é uma propriedade universal de qualquer
cifra de fluxo com combinador XOR/soma) - é uma demonstração quantificada de
por que o AtaqueColisaoIV é o teste mais crítico da suíte: a segurança inteira
depende do IV nunca repetir.
"""
struct AtaqueReusoIV <: Ataque end

nome(::AtaqueReusoIV) = "Reuso forçado de IV (two-time pad)"

function executar(a::AtaqueReusoIV, alvo::AlvoCriptografico)
    chave = chave_de_teste(alvo)
    iv_fixo = random_bytes(tamanho_iv(alvo))

    plaintext1 = "TRANSFERIR_1000"
    plaintext2 = "CANCELAR_TUDO!!"
    tamanho = max(ncodeunits(plaintext1), ncodeunits(plaintext2))

    keystream = gerar_keystream_bruto(alvo, chave, iv_fixo, "enc", tamanho)

    ciphertext1 = xor_bytes(to_buffer(plaintext1), keystream)
    ciphertext2 = xor_bytes(to_buffer(plaintext2), keystream)

    # O atacante NUNCA precisou saber a key nem o keystream - só observou os
    # dois ciphertexts (que vazariam publicamente se o IV fosse reusado) e os
    # combinou entre si.
    xor_dos_ciphertexts = xor_bytes(ciphertext1, ciphertext2)
    xor_esperado_dos_plaintexts = xor_bytes(to_buffer(plaintext1), to_buffer(plaintext2))

    vazou = xor_dos_ciphertexts == xor_esperado_dos_plaintexts

    return ResultadoAtaque(
        nome(a),
        !vazou,
        vazou ? "demonstracao" : "alta",
        vazou ?
        "Demonstração (não é falha da implementação): XOR(c1,c2) revela XOR(p1,p2) " *
        "sem precisar da chave. Inerente a qualquer combinador XOR/soma - a ÚNICA " *
        "defesa é garantir que o IV NUNCA se repita (ver Ataque de Colisão de IV)." :
        "INESPERADO: XOR dos ciphertexts não corresponde ao XOR dos plaintexts (investigar)",
        Dict{String,Any}(
            "plaintext1" => plaintext1,
            "plaintext2" => plaintext2,
            "xor_plaintexts_hex" => bytes2hex(xor_esperado_dos_plaintexts),
            "xor_ciphertexts_hex" => bytes2hex(xor_dos_ciphertexts),
        ),
    )
end
