<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Application\Env\DotEnv;
use Application\Tests\CriptografiaTest;

try {
    DotEnv::load(__DIR__ . '/.env');
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
