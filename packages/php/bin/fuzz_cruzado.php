<?php

require dirname(__DIR__) . '/vendor/autoload.php';

use Application\Seguranca\CriptografiaAlvo;

if ($argc < 3) {
    fwrite(STDERR, "Uso: php bin/fuzz_cruzado.php <entrada> <saida>\n");
    exit(1);
}

$entrada = $argv[1];
$saida = $argv[2];

$linhas = file($entrada, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if ($linhas === false) {
    fwrite(STDERR, "Não foi possível ler: {$entrada}\n");
    exit(1);
}

$alvo = new CriptografiaAlvo();
$out = fopen($saida, 'wb');
if ($out === false) {
    fwrite(STDERR, "Não foi possível escrever: {$saida}\n");
    exit(1);
}

foreach ($linhas as $indice => $linha) {
    $linha = trim($linha);
    if ($linha === '') {
        continue;
    }

    $partes = explode('|', $linha, 4);
    if (count($partes) < 4) {
        fwrite(STDERR, "Linha malformada no índice {$indice}: {$linha}\n");
        fclose($out);
        exit(1);
    }

    [$chaveHex, $ivHex, $proposito, $plaintextHex] = $partes;

    $chave = hex2bin($chaveHex);
    $iv = hex2bin($ivHex);
    $plaintext = $plaintextHex === '' ? '' : hex2bin($plaintextHex);

    $ks = $alvo->gerarKeystreamBruto($chave, $iv, $proposito, strlen($plaintext));
    $mac = $alvo->checksumBruto($plaintext, $chave);

    fwrite($out, $indice . '|' . bin2hex($ks) . '|' . bin2hex($mac) . "\n");
}

fclose($out);
