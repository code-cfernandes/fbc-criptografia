#!/usr/bin/env bash
# Ferramenta de desenvolvimento: roda um único ataque e imprime o resultado.
# uso: bash bin/testar_um.sh <NomeDoAtaque>

cd "$(dirname "$0")/.." || exit 1

source src/Core/Criptografia.sh
source src/Seguranca/ResultadoAtaque.sh
source src/Seguranca/Util.sh
source src/Seguranca/CriptografiaAlvo.sh
source src/Seguranca/SuiteDeAtaques.sh
source "src/Seguranca/Ataques/$1.sh"

alvo_init

ATQ_NOME=""
ATQ_VULNERAVEL=0
ATQ_SEVERIDADE=info
ATQ_DETALHES=""
ATQ_SKIP=0
ATQ_ERRO=0

"$1"

echo "nome=$ATQ_NOME"
echo "vulneravel=$ATQ_VULNERAVEL"
echo "severidade=$ATQ_SEVERIDADE"
echo "detalhes=$ATQ_DETALHES"
echo "skip=$ATQ_SKIP erro=$ATQ_ERRO"
