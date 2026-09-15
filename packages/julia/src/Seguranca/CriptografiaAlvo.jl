const CHAVE_PADRAO = "pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf"

"""
Liga a suíte de ataques à implementação real da cifra, expondo as camadas
internas de keystream e checksum.
"""
mutable struct CriptografiaAlvo <: AlvoCriptografico
    chave_teste::String

    function CriptografiaAlvo(chave_teste::AbstractString = CHAVE_PADRAO)
        ENV["FBC_KEY"] = chave_teste
        return new(String(chave_teste))
    end
end

encrypt(alvo::CriptografiaAlvo, texto::AbstractString) = encrypt(texto)
decrypt(alvo::CriptografiaAlvo, token::AbstractString) = decrypt(token)
prefixo(::CriptografiaAlvo) = "FBC"

function decompor(alvo::CriptografiaAlvo, buf::AbstractVector{UInt8})
    tam_iv = tamanho_iv(alvo)
    return (
        integridade = buf[1:32],
        ciphertext = buf[33:end-tam_iv],
        iv = buf[end-tam_iv+1:end],
    )
end

function recompor(::CriptografiaAlvo, campos)
    return vcat(campos.integridade, campos.ciphertext, campos.iv)
end

function gerar_keystream_bruto(
    ::CriptografiaAlvo,
    key,
    iv,
    proposito::AbstractString,
    tamanho::Integer,
)
    return gerar_keystream(to_buffer(key), to_buffer(iv), proposito, tamanho)
end

checksum_bruto(::CriptografiaAlvo, dados, key) = checksum(to_buffer(dados), to_buffer(key))

chave_de_teste(alvo::CriptografiaAlvo) = alvo.chave_teste
tamanho_iv(::CriptografiaAlvo) = 16

base64url_decode(::CriptografiaAlvo, data::AbstractString) = base64url_decode(data)
base64url_encode(::CriptografiaAlvo, data::AbstractVector{UInt8}) = base64url_encode(data)
