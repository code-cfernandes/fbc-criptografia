"""
Vetores de referência (Known Answer Tests) e interoperabilidade.

A mesma cifra é implementada em PHP, Node, TypeScript, Python, Bash, Java, Go,
Rust, Dart e Julia. Este ataque fixa keystreams e tokens conhecidos: se QUALQUER
implementação divergir, ela não reproduz estes valores e o ataque acusa.

Os tokens foram gerados com a chave de teste padrão
('pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf'); o IV é aleatório, mas fica embutido no
token, então a decifragem é determinística.
"""
struct AtaqueInteroperabilidade <: Ataque end

const CHAVE_FIXA_KAT = repeat("K", 32)

const VETORES_KAT = [
    (
        iv = "00000000000000000000000000000000",
        proposito = "enc",
        tamanho = 32,
        esperado = "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249",
    ),
    (
        iv = "00000000000000000000000000000000",
        proposito = "enc",
        tamanho = 64,
        esperado = "219a73a5bdb588b63187fa656d1492e0728c73ef526f6c525cf37cfb0f125249" *
                   "a9b8fa2ec5a08abdae48729fe50aa1def4d6af963ecb11a46d1a4604046741a7",
    ),
    (
        iv = "00000000000000000000000000000000",
        proposito = "mac",
        tamanho = 32,
        esperado = "ebaec6df127deb7dac57d584f86a13c53cfc74974da9f6594fd831acf3d07bb1",
    ),
    (
        iv = "000102030405060708090a0b0c0d0e0f",
        proposito = "enc",
        tamanho = 32,
        esperado = "0c8c9ba9ee81e6b9d00bd84b22c4180afd2a0c595f35a6be05b9d0a3ba37baf9",
    ),
    (
        iv = "000102030405060708090a0b0c0d0e0f",
        proposito = "mac",
        tamanho = 64,
        esperado = "2173c8774d071e983d895aeaa0cc2dd22d5da18b8427a98ee9ad89297eb03e0e" *
                   "961303b58b65bf2b6f48b7cfb2a04b1a7a9406f8a45605a1774d6fb8ddeda30d",
    ),
    (
        iv = "ffffffffffffffffffffffffffffffff",
        proposito = "enc",
        tamanho = 32,
        esperado = "c2e2551794dea9cd8904550745adcc28baaf0179773eb0db171dc77701edae28",
    ),
    (
        iv = "30313233343536373839616263646566",
        proposito = "enc",
        tamanho = 64,
        esperado = "ca36c5f105ea153f4dc6a591e97f7098bbc7c3aef2491423d9fb2ce612c84b72" *
                   "32009cb847d44cd2f72b47d0a293dd6227b96ce6cd2ba825e951b98e12819c0c",
    ),
    (
        iv = "30313233343536373839616263646566",
        proposito = "mac",
        tamanho = 32,
        esperado = "22aec48f7ec4731e402cc64a1b31955d7757c75c5ce606e28eb47c8ad936af3f",
    ),
]

const TOKENS_KAT = [
    (texto = "", token = "FBCbBmERldK0rQ3SAu1PxJ7drr2ie-jwhDLefEaGiBsJ_2autyPG4oSs6DXEM_w6-6x"),
    (texto = "A", token = "FBCo5OnvHbHG6nILqXCjGzVYo32jIC9I_PAqQ9CvRxggyiYKwhedK4ynN65_SSrE_mezQ"),
    (
        texto = "TESTE",
        token = "FBCn7T3VBZFYnvG41Dx4VYn-tyKKd3QheLJ1kw7oDb9EhSUEfnTtlEN2Rxp1xaskppvmGSmeTI",
    ),
    (
        texto = "mensagem de interoperabilidade entre linguagens",
        token = "FBCqgHvQ_SGLjte-SDNMHt3LyNB8qGUfMxn_N1PqWGdQmyE4iHtA3k45aAygQnBpqAXYxlwIxkDumz3ln33vAttxUwIuYExCrG-LaYLBUVEyuX49X86mScMpOd3isnqYhU",
    ),
]

nome(::AtaqueInteroperabilidade) = "Interoperabilidade e vetores conhecidos (KAT)"

function executar(a::AtaqueInteroperabilidade, alvo::AlvoCriptografico)
    falhas = String[]

    for v in VETORES_KAT
        ks = gerar_keystream_bruto(
            alvo,
            Vector{UInt8}(codeunits(CHAVE_FIXA_KAT)),
            hex2bytes(v.iv),
            v.proposito,
            v.tamanho,
        )
        if bytes2hex(ks) != v.esperado
            push!(falhas, "keystream iv=$(v.iv) prop=$(v.proposito) tam=$(v.tamanho)")
        end
    end

    for t in TOKENS_KAT
        try
            if decrypt(alvo, t.token) != t.texto
                push!(falhas, "token não decifrou para $(repr(t.texto))")
            end
        catch
            push!(falhas, "token rejeitado: $(repr(t.texto))")
        end
    end

    if !isempty(falhas)
        return ResultadoAtaque(
            nome(a),
            true,
            "alta",
            "$(length(falhas)) divergência(s) de interoperabilidade: " *
            join(falhas[1:min(5, length(falhas))], "; "),
            Dict{String,Any}("falhas" => falhas),
        )
    end

    return ResultadoAtaque(
        nome(a),
        false,
        "info",
        "$(length(VETORES_KAT)) vetores de keystream e $(length(TOKENS_KAT)) tokens de referência conferem",
    )
end
