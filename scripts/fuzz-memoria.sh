#!/usr/bin/env bash
# Fuzzing de segurança de memória em Go e Rust (decodificação de token com
# bytes arbitrários). Espera que nenhum panic/crash apareça.
#
# uso:
#   bash scripts/fuzz-memoria.sh [segundos]   # default: 300

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

segundos="${1:-300}"

# Fixa a chave explicitamente - não depende do ambiente de quem chama o
# script. Sem isso, se FBC_KEY não estiver exportada (ex: CI limpo), toda
# entrada com prefixo "FBC" falha na checagem de chave antes de chegar em
# base64/checksum/parsing, e o fuzzing inteiro testaria só esse early-return.
export FBC_KEY='pfi5j8M17ZYHohQBdutGJ5UvxWcYv4Lf'

echo "Fuzzing de memória por ${segundos}s (Go + Rust, em paralelo)..."

( cd packages/go && go test ./internal/core -run=^$ -fuzz=FuzzDecrypt -fuzztime="${segundos}s" ) \
  > /tmp/fuzz-go.log 2>&1 &
pid_go=$!

( cd packages/rust && cargo +nightly fuzz run decrypt -s none -- -max_total_time="${segundos}" ) \
  > /tmp/fuzz-rust.log 2>&1 &
pid_rust=$!

status_go=0
wait "$pid_go" || status_go=$?
status_rust=0
wait "$pid_rust" || status_rust=$?

echo
if [ "$status_go" -eq 0 ]; then
  echo "  ✅ Go:   sem crashes ($(rg -o 'execs: [0-9]+' /tmp/fuzz-go.log | tail -1))"
else
  echo "  ❌ Go:   falhou (exit $status_go) — veja /tmp/fuzz-go.log"
fi
if [ "$status_rust" -eq 0 ]; then
  echo "  ✅ Rust: sem crashes ($(rg -o 'Done [0-9]+ runs' /tmp/fuzz-rust.log | tail -1))"
else
  echo "  ❌ Rust: falhou (exit $status_rust) — veja /tmp/fuzz-rust.log"
fi

if [ "$status_go" -eq 0 ] && [ "$status_rust" -eq 0 ]; then
  exit 0
fi
exit 1
