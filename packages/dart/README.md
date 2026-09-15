# Criptografia FBC — Dart

![Dart](https://img.shields.io/badge/Dart-3.13+-0175C2?logo=dart&logoColor=white)

Implementação da cifra caseira **FBC** em Dart, com a suíte de ataques
criptográficos (fase 1: 8 ataques). Faz parte do
[monorepo Criptografia FBC](../../README.md).

Sem dependências externas — apenas `dart:convert`, `dart:io` e `dart:typed_data`.

## Requisitos

- Dart SDK 3.13+

## Estrutura

```
lib/
├── Core/Criptografia.dart         # encrypt / decrypt + gerarKeystream/checksum
└── Seguranca/
    ├── AlvoCriptografico.dart     # contrato do alvo + CamposToken
    ├── Ataque.dart                # classe abstrata dos ataques
    ├── CriptografiaAlvo.dart      # liga a suíte à cifra
    ├── ResultadoAtaque.dart       # classe + enum Severidade
    ├── SkipAtaqueException.dart
    ├── SuiteDeAtaques.dart
    ├── Util.dart
    └── Ataques/*.dart             # ataques da fase 1
bin/executar_testes.dart           # runner da suíte
```

## Como rodar

```bash
dart pub get
dart run bin/executar_testes.dart
# ou, da raiz do monorepo:
pnpm --filter @criptografia/dart test
```

O runner imprime o relatório no mesmo formato das outras linguagens e sai com
código != 0 se alguma vulnerabilidade for encontrada.

## Uso da cifra

A chave é lida de `Platform.environment['FBC_KEY']` (32 bytes):

```dart
import 'package:criptografia/Core/Criptografia.dart';

void main() {
  final token = encrypt('texto secreto');
  final texto = decrypt(token);
}
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também expõe `gerarKeystream`, `checksum`, `base64urlEncode`,
`base64urlDecode` e `definirChave` (override usado pelos testes, já que o
ambiente do processo não é mutável em tempo de execução).

## Como escrever um novo ataque

Crie `lib/Seguranca/Ataques/AtaqueX.dart` estendendo `Ataque`:

```dart
import 'package:criptografia/Seguranca/AlvoCriptografico.dart';
import 'package:criptografia/Seguranca/Ataque.dart';
import 'package:criptografia/Seguranca/ResultadoAtaque.dart';
import 'package:criptografia/Seguranca/SkipAtaqueException.dart';

class AtaqueX extends Ataque {
  @override
  String nome() => 'Nome exibido no relatório';

  @override
  ResultadoAtaque executar(AlvoCriptografico alvo) {
    // ... seu ataque ...
    // throw SkipAtaqueException('...') se o alvo não suportar
    return ResultadoAtaque(nome(), false, Severidade.info, 'detalhes');
  }
}
```

Registre em `bin/executar_testes.dart`:

```dart
suite.adicionar(AtaqueX());
```

## Notas

- Dados binários são `Uint8List`; a aritmética de 32 bits usa `& 0xFFFFFFFF`.
- A chave deve ter exatamente 32 bytes (`utf8.encode(key).length == 32`).
- `Util.dart` tem `randomInt`, `randomBytes`, `bytesToHex`, `hexToBytes`,
  `bitsDiferentes`, `contarBits1`, `shuffle` e `arrayRandKey`.
