package main

import (
	"os"

	"criptografia/internal/seguranca"
	"criptografia/internal/seguranca/ataques"
)

func main() {
	alvo := seguranca.NovoCriptografiaAlvo()

	suite := &seguranca.SuiteDeAtaques{}
	suite.
		Adicionar(ataques.NovoAtaqueIdaEVolta()).
		Adicionar(ataques.NovoAtaqueAdulteracao()).
		Adicionar(ataques.NovoAtaqueColisaoIV()).
		Adicionar(ataques.NovoAtaqueBytesFixos()).
		Adicionar(ataques.NovoAtaqueAvalanche()).
		Adicionar(ataques.NovoAtaqueDistribuicaoBytes()).
		Adicionar(ataques.NovoAtaqueFoldEstrutural()).
		Adicionar(ataques.NovoAtaqueCoberturaDependencia()).
		Adicionar(&ataques.AtaqueIVsDegenerados{}).
		Adicionar(ataques.NovoAtaqueCorrelacaoMesmoPlaintext()).
		Adicionar(&ataques.AtaqueReusoIV{}).
		Adicionar(&ataques.AtaqueVetorDeterministico{}).
		Adicionar(ataques.NovoAtaqueTiming()).
		Adicionar(ataques.NovoAtaqueColisaoChecksum()).
		Adicionar(ataques.NovoAtaqueEntropiaIV()).
		Adicionar(ataques.NovoAtaqueAvalancheChave()).
		Adicionar(ataques.NovoAtaqueAvalancheChecksum()).
		Adicionar(ataques.NovoAtaqueIndependenciaProposito()).
		Adicionar(ataques.NovoAtaqueAutocorrelacao()).
		Adicionar(&ataques.AtaqueTokensMalformados{}).
		Adicionar(ataques.NovoAtaqueChaveErrada()).
		Adicionar(ataques.NovoAtaqueComplexidadeLinear()).
		Adicionar(ataques.NovoAtaqueBateriaEstatistica()).
		Adicionar(&ataques.AtaqueCanonicalizacaoToken{}).
		Adicionar(ataques.NovoAtaqueCoberturaDependenciaIV()).
		Adicionar(ataques.NovoAtaqueSeparacaoChaveIV()).
		Adicionar(ataques.NovoAtaqueChavesDegeneradas()).
		Adicionar(ataques.NovoAtaqueSerialBits()).
		Adicionar(ataques.NovoAtaqueCusum()).
		Adicionar(ataques.NovoAtaqueEntropiaAproximada()).
		Adicionar(ataques.NovoAtaqueMensagemLonga()).
		Adicionar(ataques.NovoAtaqueIdaEVoltaBinario()).
		Adicionar(&ataques.AtaqueConfusaoCampos{}).
		Adicionar(ataques.NovoAtaqueLinearidadeChecksum()).
		Adicionar(ataques.NovoAtaqueValidacaoChave()).
		Adicionar(ataques.NovoAtaqueIntegral()).
		Adicionar(ataques.NovoAtaqueDiferencialKeystream()).
		Adicionar(ataques.NovoAtaqueDistribuicaoPorPosicao()).
		Adicionar(ataques.NovoAtaqueCorrelacaoPosicoes()).
		Adicionar(ataques.NovoAtaquePreditorDeBits()).
		Adicionar(&ataques.AtaqueInteroperabilidade{}).
		Adicionar(ataques.NovoAtaqueSAC()).
		Adicionar(ataques.NovoAtaqueBIC()).
		Adicionar(ataques.NovoAtaqueChaveRelacionada()).
		Adicionar(ataques.NovoAtaqueRotacional()).
		Adicionar(ataques.NovoAtaqueChavesFracas()).
		Adicionar(ataques.NovoAtaqueAproximacaoLinear()).
		Adicionar(ataques.NovoAtaqueCiphertextEstatistico()).
		Adicionar(ataques.NovoAtaqueMac()).
		Adicionar(ataques.NovoAtaqueLengthExtension())

	passou := suite.RodarEImprimir(alvo)
	if !passou {
		os.Exit(1)
	}
}
