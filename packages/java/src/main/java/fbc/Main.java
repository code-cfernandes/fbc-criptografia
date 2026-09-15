package fbc;

import fbc.Seguranca.CriptografiaAlvo;
import fbc.Seguranca.SuiteDeAtaques;
import fbc.Seguranca.Ataques.AtaqueAdulteracao;
import fbc.Seguranca.Ataques.AtaqueAproximacaoLinear;
import fbc.Seguranca.Ataques.AtaqueAutocorrelacao;
import fbc.Seguranca.Ataques.AtaqueAvalanche;
import fbc.Seguranca.Ataques.AtaqueAvalancheChave;
import fbc.Seguranca.Ataques.AtaqueAvalancheChecksum;
import fbc.Seguranca.Ataques.AtaqueBIC;
import fbc.Seguranca.Ataques.AtaqueBateriaEstatistica;
import fbc.Seguranca.Ataques.AtaqueBytesFixos;
import fbc.Seguranca.Ataques.AtaqueCanonicalizacaoToken;
import fbc.Seguranca.Ataques.AtaqueChaveErrada;
import fbc.Seguranca.Ataques.AtaqueChaveRelacionada;
import fbc.Seguranca.Ataques.AtaqueChavesDegeneradas;
import fbc.Seguranca.Ataques.AtaqueChavesFracas;
import fbc.Seguranca.Ataques.AtaqueCiphertextEstatistico;
import fbc.Seguranca.Ataques.AtaqueCoberturaDependencia;
import fbc.Seguranca.Ataques.AtaqueCoberturaDependenciaIV;
import fbc.Seguranca.Ataques.AtaqueColisaoChecksum;
import fbc.Seguranca.Ataques.AtaqueColisaoIV;
import fbc.Seguranca.Ataques.AtaqueComplexidadeLinear;
import fbc.Seguranca.Ataques.AtaqueConfusaoCampos;
import fbc.Seguranca.Ataques.AtaqueCorrelacaoMesmoPlaintext;
import fbc.Seguranca.Ataques.AtaqueCorrelacaoPosicoes;
import fbc.Seguranca.Ataques.AtaqueCusum;
import fbc.Seguranca.Ataques.AtaqueDiferencialKeystream;
import fbc.Seguranca.Ataques.AtaqueDistribuicaoBytes;
import fbc.Seguranca.Ataques.AtaqueDistribuicaoPorPosicao;
import fbc.Seguranca.Ataques.AtaqueEntropiaAproximada;
import fbc.Seguranca.Ataques.AtaqueEntropiaIV;
import fbc.Seguranca.Ataques.AtaqueFoldEstrutural;
import fbc.Seguranca.Ataques.AtaqueIVsDegenerados;
import fbc.Seguranca.Ataques.AtaqueIdaEVolta;
import fbc.Seguranca.Ataques.AtaqueIdaEVoltaBinario;
import fbc.Seguranca.Ataques.AtaqueIndependenciaProposito;
import fbc.Seguranca.Ataques.AtaqueIntegral;
import fbc.Seguranca.Ataques.AtaqueInteroperabilidade;
import fbc.Seguranca.Ataques.AtaqueLengthExtension;
import fbc.Seguranca.Ataques.AtaqueLinearidadeChecksum;
import fbc.Seguranca.Ataques.AtaqueMac;
import fbc.Seguranca.Ataques.AtaqueMensagemLonga;
import fbc.Seguranca.Ataques.AtaquePreditorDeBits;
import fbc.Seguranca.Ataques.AtaqueReusoIV;
import fbc.Seguranca.Ataques.AtaqueRotacional;
import fbc.Seguranca.Ataques.AtaqueSAC;
import fbc.Seguranca.Ataques.AtaqueSeparacaoChaveIV;
import fbc.Seguranca.Ataques.AtaqueSerialBits;
import fbc.Seguranca.Ataques.AtaqueTiming;
import fbc.Seguranca.Ataques.AtaqueTokensMalformados;
import fbc.Seguranca.Ataques.AtaqueValidacaoChave;
import fbc.Seguranca.Ataques.AtaqueVetorDeterministico;

/** Runner da suíte de ataques da implementação Java da cifra FBC. */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        CriptografiaAlvo alvo = new CriptografiaAlvo();

        SuiteDeAtaques suite = new SuiteDeAtaques();
        suite.adicionar(new AtaqueIdaEVolta())
                .adicionar(new AtaqueAdulteracao())
                .adicionar(new AtaqueColisaoIV())
                .adicionar(new AtaqueBytesFixos())
                .adicionar(new AtaqueAvalanche())
                .adicionar(new AtaqueDistribuicaoBytes())
                .adicionar(new AtaqueFoldEstrutural())
                .adicionar(new AtaqueCoberturaDependencia())
                .adicionar(new AtaqueIVsDegenerados())
                .adicionar(new AtaqueCorrelacaoMesmoPlaintext())
                .adicionar(new AtaqueReusoIV())
                .adicionar(new AtaqueVetorDeterministico())
                .adicionar(new AtaqueTiming())
                .adicionar(new AtaqueColisaoChecksum())
                .adicionar(new AtaqueEntropiaIV())
                .adicionar(new AtaqueAvalancheChave())
                .adicionar(new AtaqueAvalancheChecksum())
                .adicionar(new AtaqueIndependenciaProposito())
                .adicionar(new AtaqueAutocorrelacao())
                .adicionar(new AtaqueTokensMalformados())
                .adicionar(new AtaqueChaveErrada())
                .adicionar(new AtaqueComplexidadeLinear())
                .adicionar(new AtaqueBateriaEstatistica())
                .adicionar(new AtaqueCanonicalizacaoToken())
                .adicionar(new AtaqueCoberturaDependenciaIV())
                .adicionar(new AtaqueSeparacaoChaveIV())
                .adicionar(new AtaqueChavesDegeneradas())
                .adicionar(new AtaqueSerialBits())
                .adicionar(new AtaqueCusum())
                .adicionar(new AtaqueEntropiaAproximada())
                .adicionar(new AtaqueMensagemLonga())
                .adicionar(new AtaqueIdaEVoltaBinario())
                .adicionar(new AtaqueConfusaoCampos())
                .adicionar(new AtaqueLinearidadeChecksum())
                .adicionar(new AtaqueValidacaoChave())
                .adicionar(new AtaqueIntegral())
                .adicionar(new AtaqueDiferencialKeystream())
                .adicionar(new AtaqueDistribuicaoPorPosicao())
                .adicionar(new AtaqueCorrelacaoPosicoes())
                .adicionar(new AtaquePreditorDeBits())
                .adicionar(new AtaqueInteroperabilidade())
                .adicionar(new AtaqueSAC())
                .adicionar(new AtaqueBIC())
                .adicionar(new AtaqueChaveRelacionada())
                .adicionar(new AtaqueRotacional())
                .adicionar(new AtaqueChavesFracas())
                .adicionar(new AtaqueAproximacaoLinear())
                .adicionar(new AtaqueCiphertextEstatistico())
                .adicionar(new AtaqueMac())
                .adicionar(new AtaqueLengthExtension());

        boolean passou = suite.rodarEImprimir(alvo);
        System.exit(passou ? 0 : 1);
    }
}
