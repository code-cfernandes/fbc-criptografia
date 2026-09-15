"""
Entropia aproximada (ApEn), inspirado no NIST SP800-22. Mede a
previsibilidade local: para uma sequência aleatória, a chance de repetir um
bloco de m bits deve cair suavemente conforme m cresce. Estruturas
periódicas/recorrentes produzem ApEn anômala.

O estatístico chi2 = 2n(ln2 - ApEn) tem viés para n finito, então NÃO usamos
um valor esperado teórico. Comparamos o keystream com um CONTROLE de
random_bytes nas MESMAS condições - se a cifra for boa, os dois devem ser
estatisticamente indistinguíveis.
"""
struct AtaqueEntropiaAproximada <: Ataque
    tamanho::Int
    m::Int
    controles::Int
    amostras_keystream::Int
    limite_z::Float64
end

AtaqueEntropiaAproximada(;
    tamanho::Integer = 4096,
    m::Integer = 8,
    controles::Integer = 12,
    amostras_keystream::Integer = 3,
    limite_z::Real = 5.0,
) = AtaqueEntropiaAproximada(
    Int(tamanho),
    Int(m),
    Int(controles),
    Int(amostras_keystream),
    Float64(limite_z),
)

nome(::AtaqueEntropiaAproximada) = "Entropia aproximada (ApEn vs controle aleatório)"

function _bits_apen(bytes::AbstractVector{UInt8})
    bits = Int[]
    for byte in bytes
        for b in 7:-1:0
            push!(bits, Int((byte >> b) & 0x01))
        end
    end
    return bits
end

function _phi_apen(bits::AbstractVector{<:Integer}, m::Integer, n::Integer)
    total = 1 << m
    contagem = zeros(Int, total)
    janelas = n - m + 1

    for i in 0:(janelas-1)
        v = 0
        for j in 0:(m-1)
            v = (v << 1) | bits[i+j+1]
        end
        contagem[v+1] += 1
    end

    soma = 0.0
    for c in contagem
        if c > 0
            p = c / janelas
            soma += p * log(p)
        end
    end

    return soma
end

"""chi2 = 2n(ln2 - ApEn(m)), com ApEn = phi(m) - phi(m+1)."""
function _estatistico_apen(a::AtaqueEntropiaAproximada, bytes::AbstractVector{UInt8})
    bits = _bits_apen(bytes)
    n = length(bits)
    apen = _phi_apen(bits, a.m, n) - _phi_apen(bits, a.m + 1, n)
    return 2 * n * (log(2) - apen)
end

function executar(a::AtaqueEntropiaAproximada, alvo::AlvoCriptografico)
    chi_controle = Float64[]
    for _ in 1:(a.controles)
        push!(chi_controle, _estatistico_apen(a, random_bytes(a.tamanho)))
    end
    media_controle = sum(chi_controle) / length(chi_controle)
    variancia = 0.0
    for v in chi_controle
        variancia += (v - media_controle)^2
    end
    desvio_controle = sqrt(variancia / max(1, length(chi_controle) - 1))

    chi_keystream = Float64[]
    for _ in 1:(a.amostras_keystream)
        ks = gerar_keystream_bruto(
            alvo,
            chave_de_teste(alvo),
            random_bytes(tamanho_iv(alvo)),
            "enc",
            a.tamanho,
        )
        push!(chi_keystream, _estatistico_apen(a, ks))
    end
    media_keystream = sum(chi_keystream) / length(chi_keystream)

    z = desvio_controle > 0 ? (media_keystream - media_controle) / desvio_controle : 0.0
    vulneravel = abs(z) > a.limite_z

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "media" : "info",
        "chi2 keystream=$(fmt(media_keystream, 1)), controle=$(fmt(media_controle, 1)) (sd=$(fmt(desvio_controle, 1))), z=$(fmt(z, 2)) (limite=$(fmt(a.limite_z, 1)))",
        Dict{String,Any}(
            "chi_keystream" => media_keystream,
            "chi_controle" => media_controle,
            "z" => z,
        ),
    )
end
