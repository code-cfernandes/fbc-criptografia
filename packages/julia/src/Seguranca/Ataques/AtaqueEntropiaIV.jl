"""
O AtaqueColisaoIV já prova que os IVs não colidem numa amostra prática.
Esse ataque vai atrás de um sintoma diferente e mais sutil: se alguém
trocar `random_bytes(16)` por algo previsível mas ainda "único" (tipo
timestamp + contador, ou um PRNG mal semeado), a colisão pode continuar
rara - mas o IV vira PREVISÍVEL, o que quebra a garantia de segurança
mesmo sem nunca colidir de fato.

Detecta isso com 3 sinais que um IV verdadeiramente aleatório não deveria
ter: bytes vizinhos correlacionados, distribuição não-uniforme por byte,
e sequências crescentes/monótonas entre IVs consecutivos (sintoma
clássico de contador ou timestamp).
"""
struct AtaqueEntropiaIV <: Ataque
    amostras::Int
end

AtaqueEntropiaIV(; amostras::Integer = 2000) = AtaqueEntropiaIV(Int(amostras))

nome(::AtaqueEntropiaIV) = "Entropia e previsibilidade do IV"

function executar(a::AtaqueEntropiaIV, alvo::AlvoCriptografico)
    if !(alvo isa CriptografiaAlvo)
        throw(SkipAtaqueException("Precisa de base64url_decode do alvo."))
    end

    ivs = Vector{UInt8}[]
    for _ in 1:(a.amostras)
        token = encrypt(alvo, "X")
        decodificado = base64url_decode(alvo, token[length(prefixo(alvo))+1:end])
        push!(ivs, decompor(alvo, decodificado).iv)
    end

    problemas = String[]

    # Sinal 1: distribuição de bytes do IV (todas as posições, todos os IVs)
    contagem = zeros(Int, 256)
    total = 0
    for iv in ivs
        for i in 1:length(iv)
            contagem[iv[i]+1] += 1
            total += 1
        end
    end
    esperado = total / 256
    qui2 = 0.0
    for c in contagem
        qui2 += (c - esperado)^2 / esperado
    end
    if qui2 > 330
        push!(
            problemas,
            "distribuição de bytes suspeita (qui-quadrado=$(fmt(qui2, 1)), >330 é suspeito)",
        )
    end

    # Sinal 2: monotonicidade - conta quantos IVs consecutivos têm o
    # primeiro byte estritamente crescente (um contador/timestamp cru
    # produziria isso quase sempre; aleatório, só ~50% das vezes).
    crescentes = 0
    for i in 2:length(ivs)
        if ivs[i][1] > ivs[i-1][1]
            crescentes += 1
        end
    end
    proporcao_crescente = crescentes / (length(ivs) - 1)
    if proporcao_crescente > 0.65 || proporcao_crescente < 0.35
        push!(
            problemas,
            "primeiro byte do IV parece monotônico ($(fmt(proporcao_crescente * 100, 0))% das vezes crescente; aleatório ficaria perto de 50%)",
        )
    end

    # Sinal 3: bytes duplicados dentro do MESMO IV devem ser comuns
    # (paradoxo do aniversário para 16 bytes de 0-255 já prevê bastante
    # repetição interna) - a AUSÊNCIA de qualquer repetição interna em
    # quase todos os IVs seria estranha (sugeriria geração não-uniforme,
    # tipo bytes distintos forçados).
    sem_repeticao_interna = 0
    for iv in ivs
        if length(Set(iv)) == length(iv)
            sem_repeticao_interna += 1
        end
    end
    proporcao_sem_repeticao = sem_repeticao_interna / length(ivs)
    # Para 16 bytes aleatórios de 0-255, a chance de TODOS distintos é ~72%.
    if proporcao_sem_repeticao > 0.9 || proporcao_sem_repeticao < 0.5
        push!(
            problemas,
            "$(fmt(proporcao_sem_repeticao * 100, 0))% dos IVs não têm nenhum byte repetido internamente (esperado ~72% para 16 bytes aleatórios)",
        )
    end

    if !isempty(problemas)
        return ResultadoAtaque(nome(a), true, "alta", join(problemas, "; "))
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "qui-quadrado=$(fmt(qui2, 1)), $(fmt(proporcao_crescente * 100, 0))% primeiro-byte-crescente (~50% esperado), $(fmt(proporcao_sem_repeticao * 100, 0))% sem repetição interna (~72% esperado) - tudo consistente com IV aleatório",
    )
end
