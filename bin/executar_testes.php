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
    ->adicionar(new AtaqueVetorDeterministico());

$passou = $suite->rodarEImprimir($alvo);

exit($passou ? 0 : 1);
