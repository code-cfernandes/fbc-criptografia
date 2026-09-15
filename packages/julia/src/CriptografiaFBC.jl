"""
Módulo principal da implementação Julia da cifra FBC e da suíte de ataques.
"""
module CriptografiaFBC

using Base64
using Random

include("Core/Criptografia.jl")

include("Seguranca/SkipAtaqueException.jl")
include("Seguranca/ResultadoAtaque.jl")
include("Seguranca/AlvoCriptografico.jl")
include("Seguranca/Ataque.jl")
include("Seguranca/Util.jl")
include("Seguranca/CriptografiaAlvo.jl")
include("Seguranca/SuiteDeAtaques.jl")

include("Seguranca/Ataques/AtaqueIdaEVolta.jl")
include("Seguranca/Ataques/AtaqueAdulteracao.jl")
include("Seguranca/Ataques/AtaqueVetorDeterministico.jl")
include("Seguranca/Ataques/AtaqueInteroperabilidade.jl")
include("Seguranca/Ataques/AtaqueColisaoIV.jl")
include("Seguranca/Ataques/AtaqueBytesFixos.jl")
include("Seguranca/Ataques/AtaqueChaveErrada.jl")
include("Seguranca/Ataques/AtaqueValidacaoChave.jl")

export encrypt, decrypt, base64url_encode, base64url_decode, gerar_keystream, checksum,
    rot_esquerda8, rot_esquerda32, TAM_BLOCO
export AlvoCriptografico, CriptografiaAlvo, Ataque
export ResultadoAtaque, linha_resumo, SkipAtaqueException
export SuiteDeAtaques, adicionar, rodar, rodar_e_imprimir
export nome, executar, chave_de_teste, tamanho_iv, prefixo, decompor, recompor
export gerar_keystream_bruto, checksum_bruto
export random_int, random_bytes, array_rand_key
export AtaqueIdaEVolta, AtaqueAdulteracao, AtaqueVetorDeterministico,
    AtaqueInteroperabilidade, AtaqueColisaoIV, AtaqueBytesFixos, AtaqueChaveErrada,
    AtaqueValidacaoChave

end
