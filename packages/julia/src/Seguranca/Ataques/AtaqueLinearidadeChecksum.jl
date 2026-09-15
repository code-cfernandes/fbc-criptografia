"""
Procura linearidade no checksum, que seria fatal para um MAC:
 1. cs(a) XOR cs(b) == cs(a XOR b)? (linearidade sobre GF(2))
 2. para um delta d fixo, cs(a XOR d) XOR cs(a) deve ser diferente para cada
    a; se repetir muito, existe um diferencial de alta probabilidade que
    ajuda a forjar MACs.
"""
struct AtaqueLinearidadeChecksum <: Ataque
    amostras_linearidade::Int
    amostras_diferencial::Int
    tamanho_entrada::Int
end

AtaqueLinearidadeChecksum(;
    amostras_linearidade::Integer = 5000,
    amostras_diferencial::Integer = 500,
    tamanho_entrada::Integer = 32,
) = AtaqueLinearidadeChecksum(
    Int(amostras_linearidade),
    Int(amostras_diferencial),
    Int(tamanho_entrada),
)

nome(::AtaqueLinearidadeChecksum) = "Linearidade e diferenciais do checksum"

function executar(a::AtaqueLinearidadeChecksum, alvo::AlvoCriptografico)
    chave_mac = repeat("M", 32)

    relacoes_lineares = 0
    for _ in 1:(a.amostras_linearidade)
        x = random_bytes(a.tamanho_entrada)
        y = random_bytes(a.tamanho_entrada)
        lhs = xor_bytes(checksum_bruto(alvo, x, chave_mac), checksum_bruto(alvo, y, chave_mac))
        rhs = checksum_bruto(alvo, xor_bytes(x, y), chave_mac)
        if lhs == rhs
            relacoes_lineares += 1
        end
    end

    max_repeticoes_diferencial = 0
    for _ in 1:5
        delta = random_bytes(a.tamanho_entrada)
        vistos = Dict{String,Int}()
        for _ in 1:(a.amostras_diferencial)
            x = random_bytes(a.tamanho_entrada)
            dif = xor_bytes(
                checksum_bruto(alvo, xor_bytes(x, delta), chave_mac),
                checksum_bruto(alvo, x, chave_mac),
            )
            chave_dif = bytes2hex(dif)
            vistos[chave_dif] = get(vistos, chave_dif, 0) + 1
        end
        max_vistos = maximum(values(vistos))
        max_repeticoes_diferencial = max(max_repeticoes_diferencial, max_vistos)
    end

    vulneravel = relacoes_lineares > 0 || max_repeticoes_diferencial > 1

    return ResultadoAtaque(
        nome(a),
        vulneravel,
        vulneravel ? "critica" : "info",
        "$relacoes_lineares/$(a.amostras_linearidade) relações lineares; maior repetição de diferencial=$max_repeticoes_diferencial (esperado 1)",
        Dict{String,Any}(
            "relacoes_lineares" => relacoes_lineares,
            "max_repeticoes_diferencial" => max_repeticoes_diferencial,
        ),
    )
end
