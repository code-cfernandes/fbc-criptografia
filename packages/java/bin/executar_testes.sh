#!/usr/bin/env bash
# Compila e roda a suíte de ataques da implementação Java da cifra FBC.
set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf build
mkdir -p build

javac -d build $(find src -name '*.java')

java -cp build fbc.Main
