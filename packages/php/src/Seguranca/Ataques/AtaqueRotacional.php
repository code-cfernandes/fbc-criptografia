<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

/**
 * Ataque rotacional/slide: se a cifra for simétrica a deslocamentos circulares
 * de key/iv, então `keystream(rot(key), rot(iv))` seria uma rotação de
 * `keystream(key, iv)` - uma estrutura explorável. Testa todas as rotações de
 * byte e também coincidência direta do keystream.
 */
class AtaqueRotacional implements AtaqueInterface
{
    public function __construct(private int $tamanho = 64)
    {
    }

    public function nome(): string
    {
        return 'Rotacional/slide (simetria por rotação)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $chave = $alvo->chaveDeTeste();
        $iv = random_bytes($alvo->tamanhoIv());
        $ks1 = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanho);
        if ($ks1 === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $coincidencias = [];
        for ($k = 1; $k < strlen($chave); $k++) {
            $ks2 = $alvo->gerarKeystreamBruto(
                $this->rotacionar($chave, $k),
                $this->rotacionar($iv, $k),
                'enc',
                $this->tamanho,
            );

            if ($ks2 === $ks1) {
                $coincidencias[] = "rotação $k: keystream idêntico";
                continue;
            }
            $alvoRot = $this->rotacionar(substr($ks1, 0, 32), $k);
            if (substr($ks2, 0, 32) === $alvoRot) {
                $coincidencias[] = "rotação $k: keystream rotacionado";
            }
        }

        $vulneravel = !empty($coincidencias);

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $vulneravel,
            severidade: $vulneravel ? 'critica' : 'info',
            detalhes: $vulneravel
                ? 'Simetria rotacional encontrada: ' . implode('; ', array_slice($coincidencias, 0, 5))
                : 'Nenhuma das ' . (strlen($chave) - 1) . ' rotações de byte reproduziu o keystream',
            dados: ['coincidencias' => $coincidencias],
        );
    }

    private function rotacionar(string $buf, int $k): string
    {
        $n = strlen($buf);
        $out = '';
        for ($i = 0; $i < $n; $i++) {
            $out .= $buf[($i + $k) % $n];
        }
        return $out;
    }
}
