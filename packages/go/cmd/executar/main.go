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
		Adicionar(&ataques.AtaqueVetorDeterministico{}).
		Adicionar(&ataques.AtaqueInteroperabilidade{}).
		Adicionar(ataques.NovoAtaqueColisaoIV()).
		Adicionar(ataques.NovoAtaqueBytesFixos()).
		Adicionar(ataques.NovoAtaqueChaveErrada()).
		Adicionar(ataques.NovoAtaqueValidacaoChave())

	passou := suite.RodarEImprimir(alvo)
	if !passou {
		os.Exit(1)
	}
}
