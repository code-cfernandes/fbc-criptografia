<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use Application\Core\Test\Helpers\CriptografiaTest;

try {
    (new CriptografiaTest())->run();
    echo "Testes de criptografia concluídos com sucesso.\n";
} catch (\Throwable $exception) {
    fwrite(STDERR, "Falha nos testes: {$exception->getMessage()}\n");
    exit(1);
}
