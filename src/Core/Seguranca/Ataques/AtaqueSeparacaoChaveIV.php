<?php

namespace Application\Core\Seguranca\Ataques;

use Application\Core\Seguranca\AlvoCriptografico;
use Application\Core\Seguranca\AtaqueInterface;
use Application\Core\Seguranca\ResultadoAtaque;
use Application\Core\Seguranca\SkipAtaqueException;

/**
 * Testa se o keystream depende de key e iv APENAS pela combinação key XOR iv.
 * Nessa cifra o estado inicial é `a[pos] = key[pos] ^ iv[pos]`, então, se o
 * resto do gerador não reintroduzir key/iv separadamente, vale exatamente:
 *
 *     keystream(key, iv) == keystream(key ^ d, iv ^ d)
 *
 * para qualquer máscara d (com o devido alinhamento key/iv). Isso é uma
 * propriedade estrutural relevante: significa que key e iv não entram de
 * forma independente na cifra, o que enfraquece o modelo de segurança (o IV
 * deveria contribuir com entropia própria, não só deslocar a chave por XOR).
 */
class AtaqueSeparacaoChaveIV implements AtaqueInterface
{
    public function __construct(private int $tentativas = 50, private int $tamanhoBloco = 32)
    {
    }

    public function nome(): string
    {
        return 'Separação chave/IV (invariância a key XOR iv)';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        $tamChave = strlen($alvo->chaveDeTeste());
        $tamIv = $alvo->tamanhoIv();

        $primeiro = $alvo->gerarKeystreamBruto($alvo->chaveDeTeste(), random_bytes($tamIv), 'enc', $this->tamanhoBloco);
        if ($primeiro === null) {
            throw new SkipAtaqueException('Alvo não expõe gerarKeystreamBruto.');
        }

        $confirmacoes = 0;
        for ($t = 0; $t < $this->tentativas; $t++) {
            $chave = random_bytes($tamChave);
            $iv = random_bytes($tamIv);
            $d = random_bytes($tamIv);

            $chave2 = '';
            for ($p = 0; $p < $tamChave; $p++) {
                $chave2 .= chr(ord($chave[$p]) ^ ord($d[$p % $tamIv]));
            }
            $iv2 = '';
            for ($p = 0; $p < $tamIv; $p++) {
                $iv2 .= chr(ord($iv[$p]) ^ ord($d[$p]));
            }

            $ks1 = $alvo->gerarKeystreamBruto($chave, $iv, 'enc', $this->tamanhoBloco);
            $ks2 = $alvo->gerarKeystreamBruto($chave2, $iv2, 'enc', $this->tamanhoBloco);

            if ($ks1 === $ks2) {
                $confirmacoes++;
            }
        }

        $invariante = $confirmacoes === $this->tentativas;

        return new ResultadoAtaque(
            $this->nome(),
            vulneravel: $invariante,
            severidade: $invariante ? 'media' : 'info',
            detalhes: $invariante
                ? "Confirmado em {$this->tentativas}/{$this->tentativas}: keystream(key,iv) == keystream(key^d, iv^d). " .
                  'O IV só desloca a chave por XOR antes da difusão - não injeta entropia independente no key schedule.'
                : "Invariância não se confirmou ($confirmacoes/{$this->tentativas}); key e iv entram de forma independente.",
            dados: ['confirmacoes' => $confirmacoes, 'tentativas' => $this->tentativas],
        );
    }
}
