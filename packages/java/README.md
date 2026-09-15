# Criptografia FBC — Java

![Java](https://img.shields.io/badge/Java-21+-ED8B00?logo=openjdk&logoColor=white)

Implementação da cifra caseira **FBC** em Java, com a suíte de ataques
criptográficos (50 ataques). Faz parte do
[monorepo Criptografia FBC](../../README.md).

Sem dependências externas: usa apenas a biblioteca padrão (`java.security`,
`java.util.Base64`). Compilação direta com `javac`.

## Requisitos

- JDK 21+ (`javac` e `java` no PATH)

## Estrutura

```
src/main/java/fbc/
├── Main.java                        # runner da suíte
├── Core/Criptografia.java           # encrypt / decrypt + keystream/checksum
└── Seguranca/
    ├── AlvoCriptografico.java       # interface do alvo + CamposToken
    ├── AtaqueInterface.java         # interface dos ataques
    ├── CriptografiaAlvo.java        # liga a suíte à cifra
    ├── ResultadoAtaque.java         # classe + enum Severidade
    ├── Severidade.java
    ├── SkipAtaqueException.java
    ├── SuiteDeAtaques.java
    ├── Util.java
    └── Ataques/*.java               # 50 ataques
bin/executar_testes.sh               # compila e roda a suíte
```

## Como rodar

```bash
bash bin/executar_testes.sh
# ou, da raiz do monorepo:
pnpm --filter @criptografia/java test
```

O script compila tudo para `build/` (`javac -d build $(find src -name '*.java')`)
e executa `java -cp build fbc.Main`. Sai com código `!= 0` se houver
vulnerabilidade.

## Uso da cifra

A chave é lida de `FBC_KEY` (32 bytes):

```java
import fbc.Core.Criptografia;

public class Exemplo {
    public static void main(String[] args) {
        String token = Criptografia.encrypt("texto secreto");
        String texto = Criptografia.decrypt(token);
    }
}
```

Formato do token: `FBC` + base64url(`integridade[32]` . `ciphertext[n]` . `iv[16]`).

O módulo também expõe `gerarKeystream`, `checksum`, `base64urlEncode`,
`base64urlDecode` e `definirChave`.

Como Java não permite alterar variáveis de ambiente do processo, a suíte usa
`Criptografia.definirChave()` para trocar a chave durante os testes
(`AtaqueChaveErrada`, `AtaqueValidacaoChave`). Sem sobrescrita ativa, a cifra lê
`System.getenv("FBC_KEY")`.

## Como escrever um novo ataque

Crie `src/main/java/fbc/Seguranca/Ataques/AtaqueX.java`:

```java
package fbc.Seguranca.Ataques;

import fbc.Seguranca.AlvoCriptografico;
import fbc.Seguranca.AtaqueInterface;
import fbc.Seguranca.ResultadoAtaque;
import fbc.Seguranca.Severidade;
import fbc.Seguranca.SkipAtaqueException;

public class AtaqueX implements AtaqueInterface {
    @Override
    public String nome() {
        return "Nome exibido no relatório";
    }

    @Override
    public ResultadoAtaque executar(AlvoCriptografico alvo) {
        // ... seu ataque ...
        // throw new SkipAtaqueException("...") se o alvo não suportar
        return new ResultadoAtaque(nome(), false, Severidade.INFO, "detalhes");
    }
}
```

Registre em `Main.java`:

```java
suite.adicionar(new AtaqueX());
```

## Notas

- Dados binários são `byte[]`; valores de byte são lidos sem sinal (`& 0xFF`).
- A aritmética de 32 bits do checksum usa o transbordamento natural de `int`
  (equivalente ao `& 0xffffffff` das outras linguagens).
- `Util` tem `randomInt`, `randomBytes`, `bitsDiferentes`, `contarBits1`,
  `shuffle`, `arrayRandKey`, `bytesParaHex` e `hexParaBytes`.
