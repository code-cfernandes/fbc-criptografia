"""
Se a comparação de integridade não for de tempo constante (ex: usar === em vez
de hash_equals()), um atacante consegue medir QUANTOS bytes iniciais do campo
de integridade batem, comparando o tempo de resposta - e reconstruir a
integridade correta byte a byte, sem nunca saber a chave.

Esse teste gera um token válido, cria versões adulteradas onde o campo de
integridade erra em posições DIFERENTES (início vs. fim do campo), e compara o
tempo médio de decrypt() entre os grupos. Uma diferença estatisticamente clara
entre "erra logo no primeiro byte" e "erra só no último byte" indica uma
comparação vulnerável a timing.

IMPORTANTE: testes de timing têm MUITO ruído. Isso é uma checagem heurística
grosseira, não uma prova formal.
"""
struct AtaqueTiming <: Ataque
    repeticoes_por_grupo::Int
end

AtaqueTiming(; repeticoes_por_grupo::Integer = 400) =
    AtaqueTiming(Int(repeticoes_por_grupo))

nome(::AtaqueTiming) = "Timing da verificação de integridade"

function executar(a::AtaqueTiming, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_encode/decode do alvo."))
    end

    token = encrypt(alvo, "MENSAGEM_PARA_TESTE_DE_TIMING")
    pref = prefixo(alvo)
    decodificado = base64url_decode(alvo, token[length(pref)+1:end])
    campos = decompor(alvo, decodificado)
    tamanho_integridade = length(campos.integridade)

    function medir_grupo(posicao_erro::Integer)
        tempos = Vector{Int}(undef, a.repeticoes_por_grupo)
        for r in 1:(a.repeticoes_por_grupo)
            integ = copy(campos.integridade)
            integ[posicao_erro+1] = integ[posicao_erro+1] ⊻ 0x01
            campos_ad = (
                integridade = integ,
                ciphertext = campos.ciphertext,
                iv = campos.iv,
            )
            token_ad = pref * base64url_encode(alvo, recompor(alvo, campos_ad))

            inicio = time_ns()
            try
                decrypt(alvo, token_ad)
            catch
                # esperado
            end
            tempos[r] = Int(time_ns() - inicio)
        end
        sort!(tempos)
        # usa a mediana em vez da média - muito mais robusta a outliers.
        return tempos[div(length(tempos), 2)+1]
    end

    # Aquecimento para não contaminar as medianas com a compilação JIT.
    medir_grupo(0)

    medianas_a = Int[]
    medianas_b = Int[]
    for _ in 1:8
        push!(medianas_a, medir_grupo(0))
        push!(medianas_b, medir_grupo(tamanho_integridade - 1))
    end

    mediana_a = sum(medianas_a) / length(medianas_a)
    mediana_b = sum(medianas_b) / length(medianas_b)
    diferenca_relativa = abs(mediana_a - mediana_b) / max(mediana_a, mediana_b)

    # Limite arbitrário e conservador.
    vulneravel = diferenca_relativa > 0.15

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        "mediana erro-no-início=$(fmt(mediana_a, 0))ns, mediana erro-no-fim=$(fmt(mediana_b, 0))ns, diferença relativa=$(fmt(diferenca_relativa * 100, 1))% (limite=15%). " *
        (
            vulneravel ?
            "Diferença suspeita - investigar se a comparação usa hash_equals()." :
            "Sem diferença clara nesse experimento (lembrando: teste heurístico, não prova formal)."
        ),
        Dict{String,Any}("mediana_inicio_ns" => mediana_a, "mediana_fim_ns" => mediana_b),
    )
end
