"""
Estatística só do CIPHERTEXT (não do keystream): distribuição de bytes
(qui-quadrado), teste de runs nos bits e autocorrelação lag-1. Um ciphertext de
cifra sólida deve parecer ruído mesmo com plaintext variado.
"""
struct AtaqueCiphertextEstatistico <: Ataque
    amostras::Int
    tamanho_texto::Int
    z_limite::Float64
end

AtaqueCiphertextEstatistico(;
    amostras::Integer = 200,
    tamanho_texto::Integer = 64,
    z_limite::Real = 4.0,
) = AtaqueCiphertextEstatistico(Int(amostras), Int(tamanho_texto), Float64(z_limite))

nome(::AtaqueCiphertextEstatistico) =
    "Estatística do ciphertext (chi²/runs/autocorrelação)"

function executar(a::AtaqueCiphertextEstatistico, alvo::AlvoCriptografico)
    contagem = zeros(Int, 256)
    bytes = UInt8[]
    pref = prefixo(alvo)

    for _ in 1:(a.amostras)
        texto = String(random_bytes(a.tamanho_texto))
        token = encrypt(alvo, texto)
        campos = decompor(alvo, base64url_decode(alvo, token[length(pref)+1:end]))
        for b in campos.ciphertext
            contagem[b+1] += 1
            push!(bytes, b)
        end
    end

    total = length(bytes)
    esperado = total / 256
    chi2 = 0.0
    for b in 0:255
        d = contagem[b+1] - esperado
        chi2 += d * d / esperado
    end

    # runs test nos bits do ciphertext
    uns = 0
    bits = Int[]
    for b in bytes
        for k in 7:-1:0
            bit = (b >> k) & 0x01
            push!(bits, bit)
            uns += bit
        end
    end
    n = length(bits)
    pi = uns / n
    runs = 1
    for i in 2:n
        if bits[i] != bits[i-1]
            runs += 1
        end
    end
    esperado_runs = 2 * n * pi * (1 - pi)
    desvio_runs = 2 * sqrt(2 * n) * pi * (1 - pi)
    z_runs = desvio_runs > 0 ? abs(runs - esperado_runs) / desvio_runs : 0.0

    # autocorrelação lag-1
    media = sum(bytes) / total
    num = 0.0
    den = 0.0
    for i in 1:total
        den += (bytes[i] - media)^2
    end
    for i in 1:(total-1)
        num += (bytes[i] - media) * (bytes[i+1] - media)
    end
    autocorr = den > 0 ? num / den : 0.0

    problemas = String[]
    if chi2 > 330
        push!(problemas, "qui-quadrado=$(fmt(chi2, 1)) (>330 suspeito)")
    end
    if z_runs > a.z_limite
        push!(problemas, "runs z=$(fmt(z_runs, 2))")
    end
    if abs(autocorr) > 0.1
        push!(problemas, "autocorrelação=$(fmt(autocorr, 3))")
    end

    vulneravel = !isempty(problemas)

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        vulneravel ?
        join(problemas, "; ") :
        "qui-quadrado=$(fmt(chi2, 1)) sobre $total bytes, runs z=$(fmt(z_runs, 2)), autocorrelação=$(fmt(autocorr, 3)) - todos dentro do esperado",
        Dict{String,Any}("chi2" => chi2, "runs_z" => z_runs, "autocorrelacao" => autocorr),
    )
end
