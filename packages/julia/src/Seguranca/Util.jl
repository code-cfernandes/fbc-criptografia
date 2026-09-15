"""Inteiro aleatório em [min, max], inclusivo (equivalente ao random_int do PHP)."""
function random_int(min::Integer, max::Integer)
    return rand(min:max)
end

"""N bytes aleatórios (equivalente ao random_bytes do PHP)."""
function random_bytes(n::Integer)
    return rand(UInt8, n)
end

"""Converte string (binária/utf8) ou vetor de bytes para Vector{UInt8}."""
to_buffer(value::AbstractVector{UInt8}) = Vector{UInt8}(value)
to_buffer(value::AbstractString) = Vector{UInt8}(codeunits(value))

"""Popcount de um byte (0-255)."""
function contar_bits1(byte::Integer)
    x = byte & 0xFF
    count = 0
    while x != 0
        count += x & 1
        x >>= 1
    end
    return count
end

"""Conta quantos bits diferem entre dois buffers/strings de mesmo tamanho."""
function bits_diferentes(a, b)
    A = to_buffer(a)
    B = to_buffer(b)
    len = min(length(A), length(B))
    diff = 0
    for i in 1:len
        diff += contar_bits1(A[i] ⊻ B[i])
    end
    return diff
end

"""Popcount total de um buffer."""
function contar_bits_buffer(buf::AbstractVector{UInt8})
    total = 0
    for b in buf
        total += contar_bits1(b)
    end
    return total
end

"""Fisher-Yates: embaralha uma cópia do array."""
function shuffle_array(array::AbstractVector)
    out = collect(array)
    for i in length(out):-1:2
        j = random_int(1, i)
        out[i], out[j] = out[j], out[i]
    end
    return out
end

"""Chave aleatória de um objeto (equivalente ao array_rand do PHP)."""
function array_rand_key(obj)
    ks = collect(keys(obj))
    return ks[random_int(1, length(ks))]
end
