#!/usr/bin/env bash
# Roda a suíte de ataques contra a implementação bash da cifra.
#
# Uso:
#   bash bin/executar_testes.sh
#   FBC_ESCALA=10 bash bin/executar_testes.sh   # mais amostras (mais lento)

cd "$(dirname "$0")/.." || exit 1

source src/Core/Criptografia.sh
source src/Seguranca/ResultadoAtaque.sh
source src/Seguranca/Util.sh
source src/Seguranca/CriptografiaAlvo.sh
source src/Seguranca/SuiteDeAtaques.sh

ATAQUES=(
    AtaqueIdaEVolta
    AtaqueAdulteracao
    AtaqueColisaoIV
    AtaqueBytesFixos
    AtaqueAvalanche
    AtaqueDistribuicaoBytes
    AtaqueFoldEstrutural
    AtaqueCoberturaDependencia
    AtaqueIVsDegenerados
    AtaqueCorrelacaoMesmoPlaintext
    AtaqueReusoIV
    AtaqueVetorDeterministico
    AtaqueTiming
    AtaqueColisaoChecksum
    AtaqueEntropiaIV
    AtaqueAvalancheChave
    AtaqueAvalancheChecksum
    AtaqueIndependenciaProposito
    AtaqueAutocorrelacao
    AtaqueTokensMalformados
    AtaqueChaveErrada
    AtaqueComplexidadeLinear
    AtaqueBateriaEstatistica
    AtaqueCanonicalizacaoToken
    AtaqueCoberturaDependenciaIV
    AtaqueSeparacaoChaveIV
    AtaqueChavesDegeneradas
    AtaqueSerialBits
    AtaqueCusum
    AtaqueEntropiaAproximada
    AtaqueMensagemLonga
    AtaqueIdaEVoltaBinario
    AtaqueConfusaoCampos
    AtaqueLinearidadeChecksum
    AtaqueValidacaoChave
    AtaqueIntegral
    AtaqueDiferencialKeystream
    AtaqueDistribuicaoPorPosicao
    AtaqueCorrelacaoPosicoes
    AtaquePreditorDeBits
)

for ataque in "${ATAQUES[@]}"; do
    # shellcheck source=/dev/null
    source "src/Seguranca/Ataques/$ataque.sh"
done

alvo_init

suite_rodar_e_imprimir
exit $?
