<?php

namespace Application\Core\Test\Helpers;

use Application\Core\Helpers\Criptografia;
use RuntimeException;

/** Testes de ida e volta da criptografia NKC. */
final class CriptografiaTest
{
    public function run(int $iterations = 5): void
    {
        if ($iterations < 1) {
            throw new \InvalidArgumentException('A quantidade de testes deve ser maior que zero.');
        }

        for ($i = 0; $i < $iterations; $i++) {
            $this->testEncryptDecrypt("Texto de teste {$i}");
        }
    }

    public function testEncryptDecrypt(string $originalText): void
    {
        $encryptedText = Criptografia::iaCriptNKC($originalText);
        $decryptedText = Criptografia::iaDecriptNKC($encryptedText);

        if ($originalText !== $decryptedText) {
            throw new RuntimeException('O texto descriptografado não corresponde ao texto original.');
        }
    }
}
