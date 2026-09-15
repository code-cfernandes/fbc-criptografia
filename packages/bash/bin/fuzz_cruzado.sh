#!/usr/bin/env bash
# Runner de fuzzing cruzado da implementação bash.
#
# Lê fuzz/casos.txt (uma linha por caso: chave|iv|proposito|plaintext, tudo hex)
# e escreve uma linha por caso em <saida>: indice|keystream_hex|checksum_hex.
#
# Uso:
#   bash bin/fuzz_cruzado.sh <casos.txt> <resultados.txt>

cd "$(dirname "$0")/.." || exit 1

source src/Core/Criptografia.sh
source src/Seguranca/CriptografiaAlvo.sh

if [ "$#" -lt 2 ]; then
    echo "Uso: $0 <casos.txt> <resultados.txt>" >&2
    exit 1
fi

ENTRADA=$1
SAIDA=$2

# hex -> array (nameref) de bytes decimais; vazio permanece vazio.
hex_para_decimais() {
    local -n _dest=$1
    local hex=$2
    _dest=()
    [ -z "$hex" ] && return 0
    local val
    while read -r val; do
        _dest+=("$val")
    done < <(printf '%s' "$hex" | xxd -r -p | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
}

# array de bytes decimais (string "a b c") -> hex.
decimais_para_hex() {
    local -a bytes=($1)
    if [ "${#bytes[@]}" -eq 0 ]; then
        printf ''
        return 0
    fi
    printf '%02x' "${bytes[@]}"
}

: > "$SAIDA"

indice=0
while IFS='|' read -r chave_hex iv_hex proposito pt_hex; do
    hex_para_decimais chave "$chave_hex"
    hex_para_decimais iv "$iv_hex"
    hex_para_decimais plain "$pt_hex"

    string_to_bytes prop "$proposito"

    alvo_gerar_keystream_bruto ks "${chave[*]}" "${iv[*]}" "${prop[*]}" "${#plain[@]}"
    alvo_checksum_bruto mac "${plain[*]}" "${chave[*]}"

    ks_hex=$(decimais_para_hex "${ks[*]}")
    mac_hex=$(decimais_para_hex "${mac[*]}")

    printf '%d|%s|%s\n' "$indice" "$ks_hex" "$mac_hex" >> "$SAIDA"
    indice=$(( indice + 1 ))
done < "$ENTRADA"
