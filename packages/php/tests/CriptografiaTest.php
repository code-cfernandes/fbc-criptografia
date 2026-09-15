<?php

namespace Application\Tests;

use Application\Core\Criptografia;
use RuntimeException;

/** Testes de ida e volta da criptografia NKC. */
final class CriptografiaTest
{
    public function run(array $iterations = []): void
    {
        if (empty($iterations)) {
            throw new \InvalidArgumentException('A quantidade de testes deve ser maior que zero.');
        }

        foreach ($iterations as $i) {
            $this->testEncryptDecrypt($i);
        }
    }

    public function testEncryptDecrypt(string $originalText): void
    {
        $encryptedText = Criptografia::encrypt($originalText);
        $decryptedText = Criptografia::decrypt($encryptedText);
        echo "- $originalText: $encryptedText -> $decryptedText\n";

        if ($originalText !== $decryptedText) {
            throw new RuntimeException('O texto descriptografado não corresponde ao texto original.');
        }
    }
}
