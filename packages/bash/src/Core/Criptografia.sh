#!/usr/bin/env bash
TAM_BLOCO=32
DISTANCIAS_DIFUSAO=(3 5 11 19 41 3 5 11 19 41)
DIGITOS_PI='31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679'

bytes_from_stdin() {
    local -n _out=$1
    _out=()
    local val
    while read -r val; do
        _out+=("$val")
    done < <(od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
}

string_to_bytes() {
    local -n _out=$1
    local str=$2
    _out=()
    local val
    while read -r val; do
        _out+=("$val")
    done < <(printf '%s' "$str" | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
}

bytes_to_stdout() {
    local out=""
    local b
    for b in "$@"; do
        out+=$(printf '\\%03o' "$b")
    done
    printf '%b' "$out"
}

base64url_encode_stdin() {
    base64 -w0 | tr '+/' '-_' | tr -d '='
}

base64url_decode_to_array() {
    local -n _saida_dec=$1
    local data=$2

    if [[ -n "$data" && ! "$data" =~ ^[A-Za-z0-9_-]+$ ]]; then
        echo "Erro: token contém caracteres inválidos." >&2
        return 1
    fi
    local mod=$(( ${#data} % 4 ))
    if [ "$mod" -eq 1 ]; then
        echo "Erro: comprimento de token inválido." >&2
        return 1
    fi

    local padded=${data//-/+}
    padded=${padded//_//}
    if [ "$mod" -ne 0 ]; then
        local pad=$(( 4 - mod ))
        padded+=$(printf '=%.0s' $(seq 1 "$pad"))
    fi

    _saida_dec=()
    local val
    while read -r val; do
        _saida_dec+=("$val")
    done < <(printf '%s' "$padded" | base64 -d | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')

    local reencodado
    reencodado=$(bytes_to_stdout "${_saida_dec[@]}" | base64url_encode_stdin)
    if [ "$reencodado" != "$data" ]; then
        echo "Erro: token não está em forma canônica." >&2
        return 1
    fi
}

rot_esquerda8() {
    local byte=$1 n=$2
    n=$(( n & 7 ))
    if [ "$n" -eq 0 ]; then
        echo $(( byte & 0xFF ))
        return
    fi
    echo $(( ((byte << n) | (byte >> (8 - n))) & 0xFF ))
}

rot_esquerda32() {
    local val=$1 n=$2
    n=$(( n & 31 ))
    val=$(( val & 0xFFFFFFFF ))
    if [ "$n" -eq 0 ]; then
        echo "$val"
        return
    fi
    echo $(( ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF ))
}

rotacao_do_round() {
    local round_idx=$1
    local idx=$(( round_idx % ${#DIGITOS_PI} ))
    local d=${DIGITOS_PI:idx:1}
    echo $(( (d % 7) + 1 ))
}

passo() {
    local a=$1 b=$2 pos_fib=$3 round_idx=$4
    local -a prop=($5)
    local -a key=($6)
    local n
    n=$(rotacao_do_round "$round_idx")

    local soma=$(( (a + b) & 0xFF ))
    soma=$(rot_esquerda8 "$soma" "$n")
    local prop_byte=${prop[$(( pos_fib % ${#prop[@]} ))]}
    soma=$(( soma ^ prop_byte ))
    local key_byte=${key[$(( (pos_fib + round_idx) % ${#key[@]} ))]}
    soma=$(( soma ^ key_byte ))
    soma=$(( (soma * 131) & 0xFF ))

    echo "$b $soma"
}

gerar_keystream() {
    local -n _saida=$1
    local -a key=($2)
    local -a iv=($3)
    local -a prop=($4)
    local tamanho=$5

    local bloco=$TAM_BLOCO
    local iv_len=${#iv[@]}
    local key_len=${#key[@]}
    local prop_len=${#prop[@]}
    local pi_len=${#DIGITOS_PI}

    local -a a b novo_b misturado
    local pos
    for (( pos = 0; pos < bloco; pos++ )); do
        a[pos]=$(( key[pos % key_len] ^ iv[pos % iv_len] ))
        b[pos]=$(( key[(pos + 1) % key_len] ^ iv[(pos + 1) % iv_len] ))
    done

    _saida=()
    local round_idx=0
    local pos_fib_base=0
    local dist idx d n soma pf apos bpos nb rot

    while [ ${#_saida[@]} -lt "$tamanho" ]; do
        for dist in "${DISTANCIAS_DIFUSAO[@]}"; do
            idx=$(( round_idx % pi_len ))
            d=${DIGITOS_PI:idx:1}
            n=$(( (d % 7) + 1 ))

            for (( pos = 0; pos < bloco; pos++ )); do
                apos=${a[pos]}
                bpos=${b[pos]}
                soma=$(( (apos + bpos) & 0xFF ))
                if [ "$n" -ne 0 ]; then
                    soma=$(( ((soma << n) | (soma >> (8 - n))) & 0xFF ))
                fi
                pf=$(( pos_fib_base + pos ))
                soma=$(( soma ^ prop[pf % prop_len] ))
                soma=$(( soma ^ key[(pf + round_idx) % key_len] ))
                soma=$(( (soma * 131) & 0xFF ))
                a[pos]=$bpos
                novo_b[pos]=$soma
            done

            for (( pos = 0; pos < bloco; pos++ )); do
                nb=${novo_b[pos]}
                rot=$(( ((nb << 1) | (nb >> 7)) & 0xFF ))
                misturado[pos]=$(( rot ^ novo_b[(pos + dist) % bloco] ))
            done
            for (( pos = 0; pos < bloco; pos++ )); do
                b[pos]=${misturado[pos]}
            done
            round_idx=$(( round_idx + 1 ))
        done

        pos_fib_base=$(( pos_fib_base + bloco ))
        for (( pos = 0; pos < bloco; pos++ )); do
            _saida+=("${b[pos]}")
        done
    done

    _saida=("${_saida[@]:0:tamanho}")
}

xor_bytes() {
    local -n _out=$1
    local -a dados=($2)
    local -a keystream=($3)
    _out=()
    local i
    for (( i = 0; i < ${#dados[@]}; i++ )); do
        _out+=($(( dados[i] ^ keystream[i] )))
    done
}

checksum() {
    local -n _saida=$1
    local -a dados=($2)
    local -a key=($3)

    _saida=()
    local key_len=${#key[@]}
    local len=${#dados[@]}
    local rodada i k n acumulador byte

    for (( rodada = 0; rodada < 8; rodada++ )); do
        acumulador=$(( (0x811C9DC5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF ))

        for (( i = 0; i < len; i++ )); do
            byte=$(( dados[i] ^ key[(i + rodada) % key_len] ))
            acumulador=$(( (acumulador ^ byte) & 0xFFFFFFFF ))
            acumulador=$(( (acumulador * 16777619) & 0xFFFFFFFF ))
            n=$(( (i % 13) + 1 ))
            acumulador=$(( ((acumulador << n) | (acumulador >> (32 - n))) & 0xFFFFFFFF ))
        done
        for (( k = 0; k < 3; k++ )); do
            acumulador=$(( (acumulador ^ (acumulador >> 16)) & 0xFFFFFFFF ))
            acumulador=$(( (acumulador * 16777619) & 0xFFFFFFFF ))
            acumulador=$(( ((acumulador << 13) | (acumulador >> 19)) & 0xFFFFFFFF ))
        done
        _saida+=( $(( (acumulador >> 24) & 0xFF )) $(( (acumulador >> 16) & 0xFF )) $(( (acumulador >> 8) & 0xFF )) $(( acumulador & 0xFF )) )
    done
}

get_key_bytes() {
    local -n _saida_key=$1
    local _valor_env=${FBC_KEY:-}
    if [ -z "$_valor_env" ]; then
        echo "Erro: defina FBC_KEY no ambiente." >&2
        exit 1
    fi
    local -a temp
    string_to_bytes temp "$_valor_env"
    if [ "${#temp[@]}" -ne 32 ]; then
        echo "Erro: chave deve ter 32 bytes (tem ${#temp[@]})." >&2
        exit 1
    fi
    _saida_key=("${temp[@]}")
}

cripto_encrypt() {
    local texto=$1
    local -a key iv texto_bytes
    get_key_bytes key
    bytes_from_stdin iv < <(head -c 16 /dev/urandom)
    string_to_bytes texto_bytes "$texto"

    local -a enc_keystream ciphertext mac_key iv_mais_ct integridade payload
    gerar_keystream enc_keystream "${key[*]}" "${iv[*]}" "101 110 99" "${#texto_bytes[@]}"
    xor_bytes ciphertext "${texto_bytes[*]}" "${enc_keystream[*]}"

    gerar_keystream mac_key "${key[*]}" "${iv[*]}" "109 97 99" "$TAM_BLOCO"
    iv_mais_ct=("${iv[@]}" "${ciphertext[@]}")
    checksum integridade "${iv_mais_ct[*]}" "${mac_key[*]}"

    payload=("${integridade[@]}" "${ciphertext[@]}" "${iv[@]}")
    printf 'FBC%s' "$(bytes_to_stdout "${payload[@]}" | base64url_encode_stdin)"
    echo
}

cripto_decrypt() {
    local token=$1
    if [ "${token:0:3}" != "FBC" ]; then
        echo "Erro: token inválido, precisa começar com FBC." >&2
        exit 1
    fi

    local -a key decoded
    get_key_bytes key
    base64url_decode_to_array decoded "${token:3}" || exit 1

    local total=${#decoded[@]}
    local -a integridade_recebida=("${decoded[@]:0:$TAM_BLOCO}")
    local -a iv=("${decoded[@]: -16}")
    local ct_len=$(( total - TAM_BLOCO - 16 ))
    local -a ciphertext=("${decoded[@]:$TAM_BLOCO:$ct_len}")

    local -a mac_key iv_mais_ct integridade_esperada
    gerar_keystream mac_key "${key[*]}" "${iv[*]}" "109 97 99" "$TAM_BLOCO"
    iv_mais_ct=("${iv[@]}" "${ciphertext[@]}")
    checksum integridade_esperada "${iv_mais_ct[*]}" "${mac_key[*]}"

    if [ "${integridade_esperada[*]}" != "${integridade_recebida[*]}" ]; then
        echo "Erro: token adulterado ou chave incorreta." >&2
        exit 1
    fi

    local -a enc_keystream plaintext_bytes
    gerar_keystream enc_keystream "${key[*]}" "${iv[*]}" "101 110 99" "$ct_len"
    xor_bytes plaintext_bytes "${ciphertext[*]}" "${enc_keystream[*]}"

    bytes_to_stdout "${plaintext_bytes[@]}"
    echo
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -euo pipefail
    case "${1:-}" in
        encrypt)
            cripto_encrypt "$2"
            ;;
        decrypt)
            cripto_decrypt "$2"
            ;;
        *)
            echo "Uso: $0 encrypt \"texto\" | decrypt \"token\"" >&2
            exit 1
            ;;
    esac
fi