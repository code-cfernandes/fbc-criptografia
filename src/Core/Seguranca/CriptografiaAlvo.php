<?php

namespace Application\Core\Seguranca;

use Application\Core\Helpers\Criptografia;
use ReflectionClass;

/**
 * Liga a suíte de ataques à sua classe Criptografia real, usando Reflection
 * pra acessar o método privado gerarKeystream() sem precisar torná-lo público
 * só por causa dos testes.
 */
class CriptografiaAlvo implements AlvoCriptografico
{
    private ReflectionClass $reflexao;

    public function __construct(private string $chaveTeste = 'pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf')
    {
        $this->reflexao = new ReflectionClass(Criptografia::class);
        putenv('IA_CRIPT_KEY_NKC=' . $chaveTeste);
    }

    public function encrypt(string $texto): string
    {
        return Criptografia::encrypt($texto);
    }

    public function decrypt(string $token): string
    {
        return Criptografia::decrypt($token);
    }

    public function prefixo(): string
    {
        return 'FBC';
    }

    public function decompor(string $tokenDecodificado): array
    {
        return [
            'integridade' => substr($tokenDecodificado, 0, 32),
            'ciphertext'  => substr($tokenDecodificado, 32, -$this->tamanhoIv()),
            'iv'          => substr($tokenDecodificado, -$this->tamanhoIv()),
        ];
    }

    public function recompor(array $campos): string
    {
        return $campos['integridade'] . $campos['ciphertext'] . $campos['iv'];
    }

    public function gerarKeystreamBruto(string $key, string $iv, string $proposito, int $tamanho): ?string
    {
        $metodo = $this->reflexao->getMethod('gerarKeystream');
        $metodo->setAccessible(true);
        return $metodo->invoke(null, $key, $iv, $proposito, $tamanho);
    }

    public function checksumBruto(string $dados, string $key): ?string
    {
        $metodo = $this->reflexao->getMethod('checksum');
        $metodo->setAccessible(true);
        return $metodo->invoke(null, $dados, $key);
    }

    public function chaveDeTeste(): string
    {
        return $this->chaveTeste;
    }

    public function tamanhoIv(): int
    {
        return 16;
    }

    /** Ajuda os ataques a decodificar/codificar o base64url do token sem duplicar lógica. */
    public function base64urlDecode(string $data): string
    {
        return Criptografia::base64url_decode($data);
    }

    public function base64urlEncode(string $data): string
    {
        return Criptografia::base64url_encode($data);
    }
}
