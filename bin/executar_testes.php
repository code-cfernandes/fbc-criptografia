<?php

require dirname(__DIR__) . '/vendor/autoload.php';

use Application\Core\Seguranca\CriptografiaAlvo;
use Application\Core\Seguranca\SuiteDeAtaques;
use Application\Core\Seguranca\Ataques\AtaqueIdaEVolta;
use Application\Core\Seguranca\Ataques\AtaqueAdulteracao;
use Application\Core\Seguranca\Ataques\AtaqueColisaoIV;
use Application\Core\Seguranca\Ataques\AtaqueBytesFixos;
use Application\Core\Seguranca\Ataques\AtaqueAvalanche;
use Application\Core\Seguranca\Ataques\AtaqueDistribuicaoBytes;
use Application\Core\Seguranca\Ataques\AtaqueFoldEstrutural;
use Application\Core\Seguranca\Ataques\AtaqueCoberturaDependencia;
use Application\Core\Seguranca\Ataques\AtaqueIVsDegenerados;
use Application\Core\Seguranca\Ataques\AtaqueCorrelacaoMesmoPlaintext;
use Application\Core\Seguranca\Ataques\AtaqueReusoIV;
use Application\Core\Seguranca\Ataques\AtaqueVetorDeterministico;
use Application\Core\Seguranca\Ataques\AtaqueTiming;
use Application\Core\Seguranca\Ataques\AtaqueColisaoChecksum;
use Application\Core\Seguranca\Ataques\AtaqueEntropiaIV;
use Application\Core\Seguranca\Ataques\AtaqueAvalancheChave;
use Application\Core\Seguranca\Ataques\AtaqueAvalancheChecksum;
use Application\Core\Seguranca\Ataques\AtaqueIndependenciaProposito;
use Application\Core\Seguranca\Ataques\AtaqueAutocorrelacao;
use Application\Core\Seguranca\Ataques\AtaqueTokensMalformados;
use Application\Core\Seguranca\Ataques\AtaqueChaveErrada;
use Application\Core\Seguranca\Ataques\AtaqueComplexidadeLinear;
use Application\Core\Seguranca\Ataques\AtaqueBateriaEstatistica;
use Application\Core\Seguranca\Ataques\AtaqueCanonicalizacaoToken;
use Application\Core\Seguranca\Ataques\AtaqueCoberturaDependenciaIV;
use Application\Core\Seguranca\Ataques\AtaqueSeparacaoChaveIV;
use Application\Core\Seguranca\Ataques\AtaqueChavesDegeneradas;
use Application\Core\Seguranca\Ataques\AtaqueSerialBits;
use Application\Core\Seguranca\Ataques\AtaqueCusum;
use Application\Core\Seguranca\Ataques\AtaqueEntropiaAproximada;
use Application\Core\Seguranca\Ataques\AtaqueMensagemLonga;
use Application\Core\Seguranca\Ataques\AtaqueIdaEVoltaBinario;
use Application\Core\Seguranca\Ataques\AtaqueConfusaoCampos;
use Application\Core\Seguranca\Ataques\AtaqueLinearidadeChecksum;
use Application\Core\Seguranca\Ataques\AtaqueValidacaoChave;

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
    ->adicionar(new AtaqueValidacaoChave());

$passou = $suite->rodarEImprimir($alvo);

exit($passou ? 0 : 1);
