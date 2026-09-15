"""
Cifra caseira educacional — porte de Criptografia.php.

Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )

Ver Criptografia.php para os comentários completos sobre o design (difusão
tipo butterfly, distâncias Fibonacci->primo, rotação via Pi). Este arquivo
replica a lógica byte a byte, sem "melhorias" — qualquer mudança de
comportamento aqui quebraria compatibilidade com tokens gerados pelas outras
versões.
"""

const TAM_BLOCO = 32

# Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2).
const DISTANCIAS_DIFUSAO = [3, 5, 11, 19, 41, 3, 5, 11, 19, 41] # dobrado pra combater ataque integral

const DIGITOS_PI = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"

function rot_esquerda8(byte::Integer, n::Integer)
    n &= 7
    n == 0 && return byte & 0xFF
    return ((byte << n) | (byte >> (8 - n))) & 0xFF
end

function rot_esquerda32(val::Integer, n::Integer)
    n &= 31
    val &= 0xFFFFFFFF
    n == 0 && return val
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF
end

function rotacao_do_round(round_idx::Integer)
    idx = mod(round_idx, length(DIGITOS_PI)) + 1
    return mod(Int(DIGITOS_PI[idx] - '0'), 7) + 1
end

"""Um passo da recorrência tipo-Fibonacci pra uma posição do bloco."""
function _passo(a::Int, b::Int, key::Vector{Int}, proposito::Vector{Int}, pos_fib::Int, round_idx::Int)
    n = rotacao_do_round(round_idx)

    soma = (a + b) & 0xFF
    soma = rot_esquerda8(soma, n)
    soma = soma ⊻ proposito[mod(pos_fib, length(proposito)) + 1]
    # A chave participa de CADA rodada, não só do estado inicial (ver
    # comentário equivalente em Criptografia.php).
    soma = soma ⊻ key[mod(pos_fib + round_idx, length(key)) + 1]
    soma = (soma * 131) & 0xFF

    return (b, soma) # novo a = b antigo; novo b = soma
end

"""Gera `tamanho` bytes de keystream a partir de KEY + IV + propósito."""
function gerar_keystream(
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    proposito::AbstractString,
    tamanho::Integer,
)
    bloco = TAM_BLOCO
    keyv = Int.(key)
    ivv = Int.(iv)
    propv = Int.(Vector{UInt8}(codeunits(proposito)))
    key_len = length(keyv)
    iv_len = length(ivv)

    a = [keyv[mod(pos, key_len)+1] ⊻ ivv[mod(pos, iv_len)+1] for pos in 0:(bloco-1)]
    b = [keyv[mod(pos + 1, key_len)+1] ⊻ ivv[mod(pos + 1, iv_len)+1] for pos in 0:(bloco-1)]

    saida = UInt8[]
    round_idx = 0
    pos_fib_base = 0

    while length(saida) < tamanho
        for dist in DISTANCIAS_DIFUSAO
            novo_b = Vector{Int}(undef, bloco)
            for pos in 0:(bloco-1)
                novo_a, novo_bb = _passo(
                    a[pos+1],
                    b[pos+1],
                    keyv,
                    propv,
                    pos_fib_base + pos,
                    round_idx,
                )
                a[pos+1] = novo_a
                novo_b[pos+1] = novo_bb
            end

            # Combinação ASSIMÉTRICA: rotaciona só o valor próprio antes do XOR
            # (ver comentário equivalente em Criptografia.php sobre por que isso
            # é essencial — combinação simétrica colapsa metades do bloco).
            misturado = Vector{Int}(undef, bloco)
            for pos in 0:(bloco-1)
                vizinho = novo_b[mod(pos + dist, bloco)+1]
                misturado[pos+1] = rot_esquerda8(novo_b[pos+1], 1) ⊻ vizinho
            end
            b = misturado
            round_idx += 1
        end

        pos_fib_base += bloco
        append!(saida, UInt8.(b))
    end

    return saida[1:tamanho]
end

function _xor_bytes(dados::AbstractVector{UInt8}, keystream::AbstractVector{UInt8})
    return UInt8[dados[i] ⊻ keystream[i] for i in eachindex(dados)]
end

"""\"MAC\" caseiro: 8 rodadas de um checksum estilo FNV, concatenadas -> 32 bytes."""
function checksum(dados::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    saida = Vector{UInt8}(undef, 32)
    keyv = Int.(key)
    key_len = length(keyv)
    len = length(dados)

    for rodada in 0:7
        acumulador = (0x811c9dc5 ⊻ (rodada * 0x01000193)) & 0xFFFFFFFF

        for i in 0:(len-1)
            byte = Int(dados[i+1]) ⊻ keyv[mod(i + rodada, key_len)+1]
            acumulador = (acumulador ⊻ byte) & 0xFFFFFFFF
            acumulador = (acumulador * 16777619) & 0xFFFFFFFF
            acumulador = rot_esquerda32(acumulador, mod(i, 13) + 1)
        end

        # Finalização: sem isso, o último byte processado só passa por 1
        # multiply+rotate antes de virar saída, e sofre avalanche fraca
        # (medido ~25-30% em vez de ~50% nos últimos bytes do bloco de dados).
        for _ in 1:3
            acumulador = (acumulador ⊻ (acumulador >> 16)) & 0xFFFFFFFF
            acumulador = (acumulador * 16777619) & 0xFFFFFFFF
            acumulador = rot_esquerda32(acumulador, 13)
        end

        saida[rodada*4+1] = (acumulador >> 24) & 0xFF
        saida[rodada*4+2] = (acumulador >> 16) & 0xFF
        saida[rodada*4+3] = (acumulador >> 8) & 0xFF
        saida[rodada*4+4] = acumulador & 0xFF
    end

    return saida
end

function base64url_encode(data::AbstractVector{UInt8})
    s = base64encode(data)
    s = replace(s, '+' => '-', '/' => '_')
    return rstrip(s, '=')
end

function base64url_decode(data::AbstractString)
    if data != "" && !occursin(r"^[A-Za-z0-9_-]+$", data)
        throw(ArgumentError("Token contém caracteres inválidos."))
    end

    resto = mod(length(data), 4)
    if resto == 1
        throw(ArgumentError("Comprimento de token inválido."))
    end

    s = replace(data, '-' => '+', '_' => '/')
    if resto != 0
        s = s * repeat("=", 4 - resto)
    end

    decodificado = base64decode(s)

    # Canonicidade: reencoda e compara — pega bits não-canônicos no último grupo.
    if base64url_encode(decodificado) != data
        throw(ArgumentError("Token não está em forma canônica."))
    end

    return decodificado
end

function _get_key()
    chave = get(ENV, "FBC_KEY", "")
    chave_bytes = Vector{UInt8}(codeunits(chave))
    if length(chave_bytes) != 32
        throw(ArgumentError("Chave deve ter 32 bytes."))
    end
    return chave_bytes
end

function encrypt(texto::AbstractString)
    key = _get_key()
    iv = rand(UInt8, 16)
    texto_bytes = Vector{UInt8}(codeunits(texto))

    enc_keystream = gerar_keystream(key, iv, "enc", length(texto_bytes))
    ciphertext = _xor_bytes(texto_bytes, enc_keystream)

    mac_key = gerar_keystream(key, iv, "mac", TAM_BLOCO)
    integridade = checksum(vcat(iv, ciphertext), mac_key)

    return "FBC" * base64url_encode(vcat(integridade, ciphertext, iv))
end

function decrypt(texto::AbstractString)
    if !startswith(texto, "FBC")
        throw(ArgumentError("Invalid text. Text must start with FBC."))
    end

    key = _get_key()
    decodificado = base64url_decode(texto[4:end])

    integridade_recebida = decodificado[1:TAM_BLOCO]
    iv = decodificado[end-15:end]
    ciphertext = decodificado[TAM_BLOCO+1:end-16]

    mac_key = gerar_keystream(key, iv, "mac", TAM_BLOCO)
    integridade_esperada = checksum(vcat(iv, ciphertext), mac_key)

    if length(integridade_recebida) != length(integridade_esperada) ||
       integridade_esperada != integridade_recebida
        throw(ArgumentError("Token adulterado ou chave incorreta."))
    end

    enc_keystream = gerar_keystream(key, iv, "enc", length(ciphertext))
    return String(_xor_bytes(ciphertext, enc_keystream))
end
