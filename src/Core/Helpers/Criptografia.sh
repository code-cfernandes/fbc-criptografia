#!/usr/bin/env bash
#
# Cifra caseira educacional - porte pra bash puro de Criptografia.php.
#
# Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
#
# Ver Criptografia.php para os comentários completos sobre o design
# (difusão tipo butterfly, distâncias Fibonacci->primo, rotação via Pi).
# Este arquivo replica a lógica byte a byte - qualquer mudança de
# comportamento aqui quebraria compatibilidade com as outras linguagens.
#
# Uso:
#   export IA_CRIPT_KEY_NKC='sua-chave-de-32-bytes-aqui-ok!!'
#   ./criptografia.sh encrypt "texto secreto"
#   ./criptografia.sh decrypt "FBC...token..."
#
TAM_BLOCO=32
DISTANCIAS_DIFUSAO=(3 5 11 19 41)
DIGITOS_PI='31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679'

# ---------------------------------------------------------------
# Utilitários de bytes <-> string
# ---------------------------------------------------------------

# Lê bytes de um arquivo/stdin e preenche o array (nameref) com valores 0-255.
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

# Imprime os bytes do array (todos os argumentos) como binário puro no stdout.
bytes_to_stdout() {
    local out=""
    local b
    for b in "$@"; do
        out+=$(printf '\\%03o' "$b")
    done
    printf '%b' "$out"
}

# ---------------------------------------------------------------
# Base64url
# ---------------------------------------------------------------

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

    # IMPORTANTE: nunca guarda os bytes decodificados numa variável bash
    # comum - bash não suporta byte 0x00 dentro de uma string (trunca
    # silenciosamente ali), e IV/ciphertext podem ter zeros com frequência
    # normal (~1/256 por byte). Fica em "array de decimais" (seguro) o
    # tempo todo.
    _saida_dec=()
    local val
    while read -r val; do
        _saida_dec+=("$val")
    done < <(printf '%s' "$padded" | base64 -d | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')

    # Canonicidade: reencoda a partir do array e compara - pega bits
    # não-canônicos no último grupo do base64 que sobreviveriam mesmo a
    # uma checagem estrita de alfabeto.
    local reencodado
    reencodado=$(bytes_to_stdout "${_saida_dec[@]}" | base64url_encode_stdin)
    if [ "$reencodado" != "$data" ]; then
        echo "Erro: token não está em forma canônica." >&2
        return 1
    fi
}

# ---------------------------------------------------------------
# NÚCLEO: gerador de keystream com difusão tipo butterfly
# ---------------------------------------------------------------

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

# passo a b pos_fib round_idx proposito_bytes_str key_bytes_str -> "novoA novoB"
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
    # A chave participa de CADA rodada, não só do estado inicial.
    local key_byte=${key[$(( (pos_fib + round_idx) % ${#key[@]} ))]}
    soma=$(( soma ^ key_byte ))
    soma=$(( (soma * 131) & 0xFF ))

    echo "$b $soma"
}

# gerar_keystream nome_saida key_arr_str iv_arr_str proposito_arr_str tamanho
gerar_keystream() {
    local -n _saida=$1
    local -a key=($2)
    local -a iv=($3)
    local prop_str=$4
    local tamanho=$5

    local bloco=$TAM_BLOCO
    local iv_len=${#iv[@]}
    local key_len=${#key[@]}

    local -a a b novo_b misturado
    local pos
    for (( pos = 0; pos < bloco; pos++ )); do
        a[pos]=$(( key[pos % key_len] ^ iv[pos % iv_len] ))
        b[pos]=$(( key[(pos + 1) % key_len] ^ iv[(pos + 1) % iv_len] ))
    done

    _saida=()
    local round_idx=0
    local pos_fib_base=0

    while [ ${#_saida[@]} -lt "$tamanho" ]; do
        local dist
        for dist in "${DISTANCIAS_DIFUSAO[@]}"; do
            for (( pos = 0; pos < bloco; pos++ )); do
                local resultado
                resultado=$(passo "${a[pos]}" "${b[pos]}" "$(( pos_fib_base + pos ))" "$round_idx" "$prop_str" "$2")
                a[pos]=${resultado% *}
                novo_b[pos]=${resultado#* }
            done

            for (( pos = 0; pos < bloco; pos++ )); do
                local vizinho=${novo_b[$(( (pos + dist) % bloco ))]}
                local rot
                rot=$(rot_esquerda8 "${novo_b[pos]}" 1)
                misturado[pos]=$(( rot ^ vizinho ))
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

# "MAC" caseiro: 8 rodadas de checksum estilo FNV, concatenadas -> 32 bytes.
checksum() {
    local -n _saida=$1
    local -a dados=($2)
    local -a key=($3)

    _saida=()
    local key_len=${#key[@]}
    local len=${#dados[@]}
    local rodada

    for (( rodada = 0; rodada < 8; rodada++ )); do
        local acumulador=$(( (0x811C9DC5 ^ (rodada * 0x01000193)) & 0xFFFFFFFF ))
        local i
        for (( i = 0; i < len; i++ )); do
            local byte=$(( dados[i] ^ key[(i + rodada) % key_len] ))
            acumulador=$(( (acumulador ^ byte) & 0xFFFFFFFF ))
            # bash trata inteiros como 64 bits com sinal - até 0xFFFFFFFF *
            # 16777619 cabe sem estourar 63 bits, então não precisa de
            # cuidado extra tipo BigInt (diferente do porte em Node.js).
            acumulador=$(( (acumulador * 16777619) & 0xFFFFFFFF ))
            local n=$(( (i % 13) + 1 ))
            acumulador=$(rot_esquerda32 "$acumulador" "$n")
        done
        # Finalização: sem isso, o último byte processado só passa por 1
        # multiply+rotate antes de virar saída (avalanche fraca ~25-30%
        # medida nos últimos bytes do bloco de dados).
        local k
        for (( k = 0; k < 3; k++ )); do
            acumulador=$(( (acumulador ^ (acumulador >> 16)) & 0xFFFFFFFF ))
            acumulador=$(( (acumulador * 16777619) & 0xFFFFFFFF ))
            acumulador=$(rot_esquerda32 "$acumulador" 13)
        done
        _saida+=( $(( (acumulador >> 24) & 0xFF )) $(( (acumulador >> 16) & 0xFF )) $(( (acumulador >> 8) & 0xFF )) $(( acumulador & 0xFF )) )
    done
}

# ---------------------------------------------------------------
# encrypt / decrypt
# ---------------------------------------------------------------

get_key_bytes() {
    local -n _saida_key=$1
    local _valor_env=${IA_CRIPT_KEY_NKC:-}
    if [ -z "$_valor_env" ]; then
        echo "Erro: defina IA_CRIPT_KEY_NKC no ambiente." >&2
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

# ---------------------------------------------------------------
# CLI
# ---------------------------------------------------------------

# Só roda o CLI se o script for executado diretamente (não quando for
# "source"ado por outro script, como fazemos pra testar as funções isoladas).
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