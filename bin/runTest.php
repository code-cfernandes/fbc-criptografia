<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Application\Tests\Helpers\CriptografiaTest;

try {
    $tests = [
        "TESTE",
        "TESTA",
        "A",
        "AA",
        "AAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    (new CriptografiaTest())->run($tests);
    echo "Testes de criptografia concluídos com sucesso.\n";
} catch (\Throwable $exception) {
    fwrite(STDERR, "Falha nos testes: {$exception->getMessage()}\n");
    exit(1);
}
