# Changelog

Todas as mudanças relevantes deste projeto são documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e
o versionamento segue o [SemVer](https://semver.org/lang/pt-BR/).

## [1.0.0] - 2026-09-15

Primeira versão estável da suíte completa.

### Adicionado

- Cifra caseira **FBC** implementada em **10 linguagens** — PHP, Node.js,
  TypeScript, Python, Bash, Java, Go, Rust, Dart e Julia — compatíveis **byte a
  byte** entre si (mesmo vetor de referência).
- Suíte com **50 ataques criptográficos**, incluindo: ida-e-volta, adulteração,
  colisão/reuso/entropia de IV, avalanche (IV/chave/MAC), SAC, BIC, cobertura de
  dependência, fold estrutural, integral, distribuição/autocorrelação/bateria
  estatística, complexidade linear, aproximação linear, chave relacionada,
  rotacional, chaves fracas, estatística do ciphertext, força bruta/truncamento
  de MAC, length extension e **interoperabilidade (KAT)** entre linguagens.
- Infraestrutura de ataques por linguagem: `AlvoCriptografico`,
  `CriptografiaAlvo`, `ResultadoAtaque`, `SuiteDeAtaques` e utilitários.
- Monorepo **pnpm** com `pnpm test` executando todas as linguagens e
  `pnpm test:<linguagem>` para cada uma.
- Script de versionamento SemVer: `pnpm versao <major|minor|patch|x.y.z>`.

### Alterado

- **TypeScript** roda sem build (type stripping do Node 24); `tsc --noEmit`
  apenas para checagem de tipos, com `strict` e `erasableSyntaxOnly`.
- **Bash**: `gerar_keystream` e `checksum` com passo/rotações embutidos nos
  laços (~24x mais rápido), mantendo a saída idêntica.
- **Ataque serial**: troca da aproximação normal por **Wilson-Hilferty** e
  limiar `z > 6`, eliminando ~5% de falso positivo.

### Corrigido

- `AtaqueMac` não considera mais o valor original do byte na força bruta (que
  reconstruía o próprio token válido e gerava falso positivo).
