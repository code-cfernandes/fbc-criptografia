<?php

require dirname(__DIR__) . '/vendor/autoload.php';

use Application\Env\DotEnv;
use Application\Seguranca\CriptografiaAlvo;
use Application\Seguranca\SuiteDeAtaques;
use Application\Seguranca\Ataques\AtaqueIdaEVolta;
use Application\Seguranca\Ataques\AtaqueAdulteracao;
use Application\Seguranca\Ataques\AtaqueColisaoIV;
use Application\Seguranca\Ataques\AtaqueBytesFixos;
use Application\Seguranca\Ataques\AtaqueAvalanche;
use Application\Seguranca\Ataques\AtaqueDistribuicaoBytes;
use Application\Seguranca\Ataques\AtaqueFoldEstrutural;
use Application\Seguranca\Ataques\AtaqueCoberturaDependencia;
use Application\Seguranca\Ataques\AtaqueIVsDegenerados;
use Application\Seguranca\Ataques\AtaqueCorrelacaoMesmoPlaintext;
use Application\Seguranca\Ataques\AtaqueReusoIV;
use Application\Seguranca\Ataques\AtaqueVetorDeterministico;
use Application\Seguranca\Ataques\AtaqueTiming;
use Application\Seguranca\Ataques\AtaqueColisaoChecksum;
use Application\Seguranca\Ataques\AtaqueEntropiaIV;
use Application\Seguranca\Ataques\AtaqueAvalancheChave;
use Application\Seguranca\Ataques\AtaqueAvalancheChecksum;
use Application\Seguranca\Ataques\AtaqueIndependenciaProposito;
use Application\Seguranca\Ataques\AtaqueAutocorrelacao;
use Application\Seguranca\Ataques\AtaqueTokensMalformados;
use Application\Seguranca\Ataques\AtaqueChaveErrada;
use Application\Seguranca\Ataques\AtaqueComplexidadeLinear;
use Application\Seguranca\Ataques\AtaqueBateriaEstatistica;
use Application\Seguranca\Ataques\AtaqueCanonicalizacaoToken;
use Application\Seguranca\Ataques\AtaqueCoberturaDependenciaIV;
use Application\Seguranca\Ataques\AtaqueSeparacaoChaveIV;
use Application\Seguranca\Ataques\AtaqueChavesDegeneradas;
use Application\Seguranca\Ataques\AtaqueSerialBits;
use Application\Seguranca\Ataques\AtaqueCusum;
use Application\Seguranca\Ataques\AtaqueEntropiaAproximada;
use Application\Seguranca\Ataques\AtaqueMensagemLonga;
use Application\Seguranca\Ataques\AtaqueIdaEVoltaBinario;
use Application\Seguranca\Ataques\AtaqueConfusaoCampos;
use Application\Seguranca\Ataques\AtaqueLinearidadeChecksum;
use Application\Seguranca\Ataques\AtaqueValidacaoChave;
use Application\Seguranca\Ataques\AtaqueIntegral;
use Application\Seguranca\Ataques\AtaqueDiferencialKeystream;
use Application\Seguranca\Ataques\AtaqueDistribuicaoPorPosicao;
use Application\Seguranca\Ataques\AtaqueCorrelacaoPosicoes;
use Application\Seguranca\Ataques\AtaquePreditorDeBits;
use Application\Seguranca\Ataques\AtaqueInteroperabilidade;
use Application\Seguranca\Ataques\AtaqueSAC;
use Application\Seguranca\Ataques\AtaqueBIC;
use Application\Seguranca\Ataques\AtaqueChaveRelacionada;
use Application\Seguranca\Ataques\AtaqueRotacional;
use Application\Seguranca\Ataques\AtaqueChavesFracas;
use Application\Seguranca\Ataques\AtaqueAproximacaoLinear;
use Application\Seguranca\Ataques\AtaqueCiphertextEstatistico;
use Application\Seguranca\Ataques\AtaqueMac;
use Application\Seguranca\Ataques\AtaqueLengthExtension;

DotEnv::load(__DIR__ . '/.env');

$alvo = new CriptografiaAlvo();

$suite = new SuiteDeAtaques();
$suite
    ->adicionar(new AtaqueIdaEVolta())
    ->adicionar(new AtaqueAdulteracao())
    ->adicionar(new AtaqueColisaoIV())
    ->adicionar(new AtaqueBytesFixos())
    ->adicionar(new AtaqueAvalanche())
    ->adicionar(new AtaqueDistribuicaoBytes())
    ->adicionar(new AtaqueFoldEstrutural())
    ->adicionar(new AtaqueCoberturaDependencia())
    ->adicionar(new AtaqueIVsDegenerados())
    ->adicionar(new AtaqueCorrelacaoMesmoPlaintext())
    ->adicionar(new AtaqueReusoIV())
    ->adicionar(new AtaqueVetorDeterministico())
    ->adicionar(new AtaqueTiming())
    ->adicionar(new AtaqueColisaoChecksum())
    ->adicionar(new AtaqueEntropiaIV())
    ->adicionar(new AtaqueAvalancheChave())
    ->adicionar(new AtaqueAvalancheChecksum())
    ->adicionar(new AtaqueIndependenciaProposito())
    ->adicionar(new AtaqueAutocorrelacao())
    ->adicionar(new AtaqueTokensMalformados())
    ->adicionar(new AtaqueChaveErrada())
    ->adicionar(new AtaqueComplexidadeLinear())
    ->adicionar(new AtaqueBateriaEstatistica())
    ->adicionar(new AtaqueCanonicalizacaoToken())
    ->adicionar(new AtaqueCoberturaDependenciaIV())
    ->adicionar(new AtaqueSeparacaoChaveIV())
    ->adicionar(new AtaqueChavesDegeneradas())
    ->adicionar(new AtaqueSerialBits())
    ->adicionar(new AtaqueCusum())
    ->adicionar(new AtaqueEntropiaAproximada())
    ->adicionar(new AtaqueMensagemLonga())
    ->adicionar(new AtaqueIdaEVoltaBinario())
    ->adicionar(new AtaqueConfusaoCampos())
    ->adicionar(new AtaqueLinearidadeChecksum())
    ->adicionar(new AtaqueValidacaoChave())
    ->adicionar(new AtaqueIntegral())
    ->adicionar(new AtaqueDiferencialKeystream())
    ->adicionar(new AtaqueDistribuicaoPorPosicao())
    ->adicionar(new AtaqueCorrelacaoPosicoes())
    ->adicionar(new AtaquePreditorDeBits())
    ->adicionar(new AtaqueInteroperabilidade())
    ->adicionar(new AtaqueSAC())
    ->adicionar(new AtaqueBIC())
    ->adicionar(new AtaqueChaveRelacionada())
    ->adicionar(new AtaqueRotacional())
    ->adicionar(new AtaqueChavesFracas())
    ->adicionar(new AtaqueAproximacaoLinear())
    ->adicionar(new AtaqueCiphertextEstatistico())
    ->adicionar(new AtaqueMac())
    ->adicionar(new AtaqueLengthExtension());

$passou = $suite->rodarEImprimir($alvo);

exit($passou ? 0 : 1);
