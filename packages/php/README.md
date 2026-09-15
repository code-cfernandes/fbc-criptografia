# Criptografia FBC — PHP

![PHP](https://img.shields.io/badge/PHP-8.3+-777BB4?logo=php&logoColor=white)

Implementação da cifra caseira **FBC** em PHP, com a suíte de 50 ataques
criptográficos. Faz parte do [monorepo Criptografia FBC](../../README.md).

## Requisitos

- PHP 8.3+
- Composer

## Estrutura

```
src/
├── Core/Criptografia.php          # encrypt / decrypt
├── Env/DotEnv.php                 # leitura de .env
└── Seguranca/
    ├── AlvoCriptografico.php      # contrato do alvo
    ├── AtaqueInterface.php        # contrato dos ataques
    ├── CriptografiaAlvo.php       # liga a suíte à cifra (via Reflection)
    ├── ResultadoAtaque.php
    ├── SkipAtaqueException.php
    ├── SuiteDeAtaques.php
    └── Ataques/*.php              # 50 ataques
bin/
├── executar_testes.php            # runner da suíte
└── runTest.php                    # ida-e-volta básica
tests/CriptografiaTest.php
```

O autoload é PSR-4: `Application\` → `src/` e `Application\Tests\` → `tests/`.

## Como rodar

```bash
composer install
composer suite   # suíte de ataques (php bin/executar_testes.php)
composer test    # ida-e-volta básica (php bin/runTest.php)
```

## Uso da cifra

A chave é lida de `FBC_KEY` (via `getenv`). O `runTest.php` carrega a chave de
`bin/.env` com `Application\Env\DotEnv`:

```php
putenv('FBC_KEY=uma-chave-de-32-bytes-aqui-ok!!');

use Application\Core\Criptografia;

$token = Criptografia::encrypt('texto secreto');
$texto = Criptografia::decrypt($token);
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

## Como escrever um novo ataque

Crie `src/Seguranca/Ataques/AtaqueX.php` implementando `AtaqueInterface`:

```php
<?php

namespace Application\Seguranca\Ataques;

use Application\Seguranca\AlvoCriptografico;
use Application\Seguranca\AtaqueInterface;
use Application\Seguranca\ResultadoAtaque;
use Application\Seguranca\SkipAtaqueException;

class AtaqueX implements AtaqueInterface
{
    public function nome(): string
    {
        return 'Nome exibido no relatório';
    }

    public function executar(AlvoCriptografico $alvo): ResultadoAtaque
    {
        // ... seu ataque ...
        // throw new SkipAtaqueException('...') se o alvo não suportar
        return new ResultadoAtaque($this->nome(), false, 'info', 'detalhes');
    }
}
```

Registre em `bin/executar_testes.php`:

```php
$suite->adicionar(new AtaqueX());
```

## Notas

- `CriptografiaAlvo` acessa `gerarKeystream()` e `checksum()` internos via
  `Reflection`, sem torná-los públicos.
- `ResultadoAtaque` recebe `(nome, vulneravel, severidade, detalhes, dados)`.
- O `AtaqueVetorDeterministico` imprime o vetor de referência compartilhado entre
  as linguagens.
