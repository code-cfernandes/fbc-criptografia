<?php

namespace Application\Env;

use InvalidArgumentException;
use RuntimeException;

/** Carrega configurações de um arquivo .env. */
final class DotEnv
{
    /** @var array<string, string> */
    private static array $values = [];
    private static bool $defaultLoaded = false;

    /**
     * Carrega um arquivo .env. Sem caminho, procura o .env na raiz do projeto.
     * Variáveis já existentes no processo têm precedência, salvo com $override.
     */
    public static function load(?string $path = null, bool $override = false): void
    {
        $path ??= dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.env';
        if (is_dir($path)) {
            $path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.env';
        }

        if (!is_file($path)) {
            if ($path === dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.env') {
                self::$defaultLoaded = true;
                return;
            }

            throw new RuntimeException(sprintf('Arquivo .env não encontrado: %s', $path));
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            throw new RuntimeException(sprintf('Não foi possível ler o arquivo .env: %s', $path));
        }

        foreach ($lines as $number => $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (str_starts_with($line, 'export ')) {
                $line = ltrim(substr($line, 7));
            }

            $separator = strpos($line, '=');
            if ($separator === false) {
                throw new InvalidArgumentException(sprintf('Linha .env inválida (%d).', $number + 1));
            }

            $key = trim(substr($line, 0, $separator));
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $key) !== 1) {
                throw new InvalidArgumentException(sprintf('Nome de variável inválido na linha %d.', $number + 1));
            }

            $value = self::parseValue(trim(substr($line, $separator + 1)));
            if (!$override && self::environmentValue($key) !== null) {
                continue;
            }

            self::$values[$key] = $value;
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
            putenv($key . '=' . $value);
        }

        self::$defaultLoaded = true;
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        if (!self::$defaultLoaded) {
            self::load();
        }

        return self::environmentValue($key) ?? self::$values[$key] ?? $default;
    }

    public static function has(string $key): bool
    {
        return self::get($key) !== null;
    }

    /** @return array<string, string> */
    public static function all(): array
    {
        if (!self::$defaultLoaded) {
            self::load();
        }

        return self::$values;
    }

    private static function environmentValue(string $key): ?string
    {
        $value = getenv($key);
        if ($value !== false) {
            return $value;
        }

        if (isset($_ENV[$key])) {
            return (string) $_ENV[$key];
        }
        if (isset($_SERVER[$key])) {
            return (string) $_SERVER[$key];
        }

        return null;
    }

    private static function parseValue(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $quote = $value[0];
        if (($quote === '"' || $quote === "'") && str_ends_with($value, $quote)) {
            $value = substr($value, 1, -1);
            return $quote === '"' ? stripcslashes($value) : str_replace(["\\\\", "\\'"], ["\\", "'"], $value);
        }

        return preg_replace('/\s+#.*$/', '', $value) ?? $value;
    }
}
