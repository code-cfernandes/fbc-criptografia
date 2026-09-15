#!/usr/bin/env julia
# Harness de regressão histórica.
#
# Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
# bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
# (vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
# PRECISA resistir (vulneravel=false).

include(joinpath(@__DIR__, "..", "src", "CriptografiaFBC.jl"))
using .CriptografiaFBC
using Base64

# Estende as funções genéricas do módulo com as versões com bug.
import .CriptografiaFBC:
    encrypt, decrypt, gerar_keystream_bruto, checksum_bruto, base64url_decode, chave_de_teste

const DIGITOS_PI =
    "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"

_para_bytes(v::AbstractString) = Vector{UInt8}(codeunits(v))
_para_bytes(v::AbstractVector{UInt8}) = Vector{UInt8}(v)

function _xor(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})
    return UInt8[a[i] ⊻ b[i] for i in 1:min(length(a), length(b))]
end

function _rotacao_do_round(round_idx::Integer)
    idx = mod(round_idx, length(DIGITOS_PI)) + 1
    return mod(Int(DIGITOS_PI[idx] - '0'), 7) + 1
end

# passo com mutações: bug 5 remove a reinserção da chave em cada rodada.
function _passo_com_bug(bug, a, b, keyv, propv, pos_fib, round_idx)
    n = _rotacao_do_round(round_idx)
    soma = (a + b) & 0xFF
    soma = rot_esquerda8(soma, n)
    soma = soma ⊻ propv[mod(pos_fib, length(propv)) + 1]
    if bug != 5
        soma = soma ⊻ keyv[mod(pos_fib + round_idx, length(keyv)) + 1]
    end
    soma = (soma * 131) & 0xFF
    return (b, soma)
end

# gerar_keystream com mutações: bugs 1, 2, 4, 5.
function _gerar_keystream_com_bug(
    bug,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    proposito::AbstractString,
    tamanho::Integer,
)
    if bug == 1
        # bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
        return gerar_keystream(key, zeros(UInt8, length(iv)), proposito, tamanho)
    end

    bloco = TAM_BLOCO
    # bug 2: o colapso de metades só acontece quando a distância é exatamente
    # metade do bloco (16) — reproduzimos a condição histórica.
    distancias = if bug == 4
        [3]
    elseif bug == 2
        [3, 5, 11, 19, 41, 16]
    else
        [3, 5, 11, 19, 41, 3, 5, 11, 19, 41]
    end
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
        for dist in distancias
            novo_b = Vector{Int}(undef, bloco)
            for pos in 0:(bloco-1)
                novo_a, novo_bb = _passo_com_bug(
                    bug,
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

            misturado = Vector{Int}(undef, bloco)
            for pos in 0:(bloco-1)
                vizinho = novo_b[mod(pos + dist, bloco)+1]
                if bug == 2
                    # bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                    misturado[pos+1] = rot_esquerda8(novo_b[pos+1] ⊻ vizinho, 1)
                else
                    misturado[pos+1] = rot_esquerda8(novo_b[pos+1], 1) ⊻ vizinho
                end
            end
            b = misturado
            round_idx += 1
        end

        pos_fib_base += bloco
        append!(saida, UInt8.(b))
    end

    return saida[1:tamanho]
end

# checksum com mutação: bug 3 remove a finalização.
function _checksum_com_bug(bug, dados::AbstractVector{UInt8}, key::AbstractVector{UInt8})
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

        if bug != 3
            for _ in 1:3
                acumulador = (acumulador ⊻ (acumulador >> 16)) & 0xFFFFFFFF
                acumulador = (acumulador * 16777619) & 0xFFFFFFFF
                acumulador = rot_esquerda32(acumulador, 13)
            end
        end

        saida[rodada*4+1] = (acumulador >> 24) & 0xFF
        saida[rodada*4+2] = (acumulador >> 16) & 0xFF
        saida[rodada*4+3] = (acumulador >> 8) & 0xFF
        saida[rodada*4+4] = acumulador & 0xFF
    end

    return saida
end

# base64url decode com mutação: bug 6 aceita alfabeto padrão e lixo.
function _base64url_decode_com_bug(bug, data::AbstractString)
    if bug != 6
        return base64url_decode(data)
    end
    s = replace(data, '-' => '+', '_' => '/')
    s = replace(s, r"[^A-Za-z0-9+/=]" => "")
    resto = mod(length(s), 4)
    if resto != 0
        s = s * repeat("=", 4 - resto)
    end
    return base64decode(s)
end

# Alvo que aponta para a cifra com o bug selecionado. Herda de
# `CriptografiaAlvo` (abstrato) e sobrescreve só os métodos com bug.
struct SnapshotAlvo <: CriptografiaAlvo
    chave_teste::String
    bug::Int
end

SnapshotAlvo(bug::Integer) = SnapshotAlvo(CriptografiaFBC.CHAVE_PADRAO, Int(bug))

chave_de_teste(alvo::SnapshotAlvo) = alvo.chave_teste

function gerar_keystream_bruto(
    alvo::SnapshotAlvo,
    key,
    iv,
    proposito::AbstractString,
    tamanho::Integer,
)
    return _gerar_keystream_com_bug(alvo.bug, _para_bytes(key), _para_bytes(iv), proposito, tamanho)
end

checksum_bruto(alvo::SnapshotAlvo, dados, key) =
    _checksum_com_bug(alvo.bug, _para_bytes(dados), _para_bytes(key))

base64url_decode(alvo::SnapshotAlvo, data::AbstractString) =
    _base64url_decode_com_bug(alvo.bug, data)

function encrypt(alvo::SnapshotAlvo, texto::AbstractString)
    key = _para_bytes(alvo.chave_teste)
    iv = rand(UInt8, 16)
    texto_bytes = _para_bytes(texto)
    ks = gerar_keystream_bruto(alvo, key, iv, "enc", length(texto_bytes))
    ct = _xor(texto_bytes, ks)
    mac_key = gerar_keystream_bruto(alvo, key, iv, "mac", TAM_BLOCO)
    integridade = checksum_bruto(alvo, vcat(iv, ct), mac_key)
    return "FBC" * base64url_encode(vcat(integridade, ct, iv))
end

function decrypt(alvo::SnapshotAlvo, token::AbstractString)
    if !startswith(token, "FBC")
        throw(ArgumentError("Invalid text. Text must start with FBC."))
    end
    key = _para_bytes(alvo.chave_teste)
    decodificado = base64url_decode(alvo, token[4:end])
    integ = decodificado[1:32]
    iv = decodificado[end-15:end]
    ct = decodificado[33:end-16]
    mac_key = gerar_keystream_bruto(alvo, key, iv, "mac", TAM_BLOCO)
    esperado = checksum_bruto(alvo, vcat(iv, ct), mac_key)
    if esperado != integ
        throw(ArgumentError("Token adulterado ou chave incorreta."))
    end
    ks = gerar_keystream_bruto(alvo, key, iv, "enc", length(ct))
    return String(_xor(ct, ks))
end

casos = [
    (1, "keystream ignora o IV", AtaqueCorrelacaoMesmoPlaintext()),
    (2, "combinador simétrico (metades colapsam)", AtaqueFoldEstrutural()),
    (3, "checksum sem finalização", AtaqueAvalancheChecksum()),
    (4, "cinco rodadas de difusão", AtaqueIntegral()),
    (5, "chave só no estado inicial", AtaqueSeparacaoChaveIV()),
    (6, "base64 não estrito", AtaqueCanonicalizacaoToken()),
]

println("="^72)
println("REGRESSÃO HISTÓRICA")
println("="^72)

falhas = 0
for (bug, descricao, ataque) in casos
    snapshot = SnapshotAlvo(bug)
    real = CriptografiaAlvo()

    local r_snapshot
    local r_real
    try
        r_snapshot = executar(ataque, snapshot)
        r_real = executar(ataque, real)
    catch e
        println("  ❌ bug $bug ($descricao): erro — $(sprint(showerror, e))")
        global falhas += 1
        continue
    end

    detectou = r_snapshot.vulneravel == true
    resistiu = r_real.vulneravel == false
    ok = detectou && resistiu
    if !ok
        global falhas += 1
    end

    println(
        "  $(ok ? "✅" : "❌") bug $bug ($descricao): " *
        "snapshot $(detectou ? "detectado" : "NÃO detectado") | " *
        "atual $(resistiu ? "resistiu" : "ACUSOU")",
    )
    if !ok
        println("       snapshot: $(linha_resumo(r_snapshot))")
        println("       atual:    $(linha_resumo(r_real))")
    end
end

println("="^72)
if falhas == 0
    println("RESUMO: $(length(casos)) bugs históricos detectados; código atual resiste a todos.")
else
    println("RESUMO: $falhas caso(s) falharam.")
end
println("="^72)

exit(falhas == 0 ? 0 : 1)
