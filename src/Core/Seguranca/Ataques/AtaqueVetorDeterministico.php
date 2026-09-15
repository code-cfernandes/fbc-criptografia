<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Com KEY e IV fixos, o keystream gerado precisa ser 100% determinístico -
 * chamar a função duas vezes com a mesma entrada tem que dar o mesmo
 * resultado, sempre. Se não der, alguma fonte de aleatoriedade (relógio,
 * random_bytes, uniqid, etc.) vazou pra dentro de uma função que deveria
 * ser pura - isso quebraria o decrypt() em produção de forma intermitente
 * e seria um pesadelo de debugar.
 *
 * De brinde, esse ataque imprime o "vetor de referência" (Known Answer
 * Vector) pra esse par key/iv - guarde esse valor: se ele mudar entre
 * versões do código sem você ter mexido de propósito na lógica de mistura,
 * é sinal de uma regressão acidental.
 */
class AtaqueVetorDeterministico implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Determinismo (vetor de referência key/iv fixos)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chaveFixa = str_repeat('K', strlen($alvo->chaveDeTeste())); // chave fixa e conhecida
        $ivFixo = str_repeat("\x00", $alvo->tamanhoIv());            // IV fixo (só pra este teste)

        $ks1 = $alvo->gerarKeystreamBruto($chaveFixa, $ivFixo, 'enc', 32);
        if ($ks1 === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }
        $ks2 = $alvo->gerarKeystreamBruto($chaveFixa, $ivFixo, 'enc', 32);
        $ks3 = $alvo->gerarKeystreamBruto($chaveFixa, $ivFixo, 'enc', 32);

        $determinístico = ($ks1 === $ks2) && ($ks2 === $ks3);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: !$determinístico,
            severidade: $determinístico ? 'info' : 'critica',
            detalhes: $determinístico
                ? 'Determinístico em 3 chamadas. Vetor de referência (key=64x"K", iv=zeros, prop=enc, 32 bytes): ' . bin2hex($ks1)
                : 'NÃO determinístico! 3 chamadas com a mesma entrada deram resultados diferentes: ' . bin2hex($ks1) . ' / ' . bin2hex($ks2) . ' / ' . bin2hex($ks3),
            dados: ['vetor_hex' => bin2hex($ks1)],
        );
    }
}