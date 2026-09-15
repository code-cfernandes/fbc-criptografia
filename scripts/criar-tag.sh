#!/usr/bin/env bash
# Cria a tag anotada da versão atual (lê o package.json da raiz e o CHANGELOG).
#
# uso:
#   bash scripts/criar-tag.sh          # cria v<versao> em HEAD
#
# Requer a árvore de trabalho limpa (tudo commitado).

set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

versao=$(node -p "require('./package.json').version")
tag="v${versao}"

if [ -n "$(git status --porcelain)" ]; then
    echo "Árvore de trabalho suja. Faça o commit antes de criar a tag." >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    echo "A tag ${tag} já existe." >&2
    exit 1
fi

# Extrai a seção da versão no CHANGELOG (sem o cabeçalho "## [x.y.z]").
mensagem=$(awk -v v="$versao" '
    index($0, "## [" v "]") == 1 { captura = 1; next }
    captura && index($0, "## [") == 1 { captura = 0 }
    captura { print }
' CHANGELOG.md)

git tag -a "$tag" --cleanup=verbatim -m "Versão ${versao}" -m "${mensagem}"

echo "Tag ${tag} criada:"
git show --no-patch --format='%H %d' "$tag"
