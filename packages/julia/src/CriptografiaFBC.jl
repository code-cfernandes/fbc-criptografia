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

include("Seguranca/Ataques/AtaqueAvalanche.jl")
include("Seguranca/Ataques/AtaqueAvalancheChave.jl")
include("Seguranca/Ataques/AtaqueAvalancheChecksum.jl")
include("Seguranca/Ataques/AtaqueAutocorrelacao.jl")
include("Seguranca/Ataques/AtaqueBateriaEstatistica.jl")
include("Seguranca/Ataques/AtaqueCanonicalizacaoToken.jl")
include("Seguranca/Ataques/AtaqueChavesDegeneradas.jl")
include("Seguranca/Ataques/AtaqueCoberturaDependencia.jl")
include("Seguranca/Ataques/AtaqueCoberturaDependenciaIV.jl")
include("Seguranca/Ataques/AtaqueColisaoChecksum.jl")
include("Seguranca/Ataques/AtaqueComplexidadeLinear.jl")
include("Seguranca/Ataques/AtaqueConfusaoCampos.jl")
include("Seguranca/Ataques/AtaqueCorrelacaoMesmoPlaintext.jl")
include("Seguranca/Ataques/AtaqueCorrelacaoPosicoes.jl")
include("Seguranca/Ataques/AtaqueCusum.jl")
include("Seguranca/Ataques/AtaqueDiferencialKeystream.jl")
include("Seguranca/Ataques/AtaqueDistribuicaoBytes.jl")
include("Seguranca/Ataques/AtaqueDistribuicaoPorPosicao.jl")
include("Seguranca/Ataques/AtaqueEntropiaAproximada.jl")
include("Seguranca/Ataques/AtaqueEntropiaIV.jl")
include("Seguranca/Ataques/AtaqueFoldEstrutural.jl")

include("Seguranca/Ataques/AtaqueIdaEVoltaBinario.jl")
include("Seguranca/Ataques/AtaqueIndependenciaProposito.jl")
include("Seguranca/Ataques/AtaqueIntegral.jl")
include("Seguranca/Ataques/AtaqueIVsDegenerados.jl")
include("Seguranca/Ataques/AtaqueLinearidadeChecksum.jl")
include("Seguranca/Ataques/AtaqueMensagemLonga.jl")
include("Seguranca/Ataques/AtaquePreditorDeBits.jl")
include("Seguranca/Ataques/AtaqueReusoIV.jl")
include("Seguranca/Ataques/AtaqueSeparacaoChaveIV.jl")
include("Seguranca/Ataques/AtaqueSerialBits.jl")
include("Seguranca/Ataques/AtaqueTiming.jl")
include("Seguranca/Ataques/AtaqueTokensMalformados.jl")
include("Seguranca/Ataques/AtaqueSAC.jl")
include("Seguranca/Ataques/AtaqueBIC.jl")
include("Seguranca/Ataques/AtaqueChaveRelacionada.jl")
include("Seguranca/Ataques/AtaqueRotacional.jl")
include("Seguranca/Ataques/AtaqueChavesFracas.jl")
include("Seguranca/Ataques/AtaqueAproximacaoLinear.jl")
include("Seguranca/Ataques/AtaqueCiphertextEstatistico.jl")
include("Seguranca/Ataques/AtaqueMac.jl")
include("Seguranca/Ataques/AtaqueLengthExtension.jl")

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
export AtaqueAvalanche, AtaqueAvalancheChave, AtaqueAvalancheChecksum,
    AtaqueAutocorrelacao, AtaqueBateriaEstatistica, AtaqueCanonicalizacaoToken,
    AtaqueChavesDegeneradas, AtaqueCoberturaDependencia, AtaqueCoberturaDependenciaIV,
    AtaqueColisaoChecksum, AtaqueComplexidadeLinear, AtaqueConfusaoCampos,
    AtaqueCorrelacaoMesmoPlaintext, AtaqueCorrelacaoPosicoes, AtaqueCusum,
    AtaqueDiferencialKeystream, AtaqueDistribuicaoBytes, AtaqueDistribuicaoPorPosicao,
    AtaqueEntropiaAproximada, AtaqueEntropiaIV, AtaqueFoldEstrutural
export AtaqueIdaEVoltaBinario, AtaqueIndependenciaProposito, AtaqueIntegral,
    AtaqueIVsDegenerados, AtaqueLinearidadeChecksum, AtaqueMensagemLonga,
    AtaquePreditorDeBits, AtaqueReusoIV, AtaqueSeparacaoChaveIV, AtaqueSerialBits,
    AtaqueTiming, AtaqueTokensMalformados, AtaqueSAC, AtaqueBIC,
    AtaqueChaveRelacionada, AtaqueRotacional, AtaqueChavesFracas,
    AtaqueAproximacaoLinear, AtaqueCiphertextEstatistico, AtaqueMac,
    AtaqueLengthExtension

end
