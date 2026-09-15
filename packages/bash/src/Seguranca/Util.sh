# Utilitários compartilhados pelos ataques.
#
# Dados binários circulam sempre como arrays de decimais (0-255) convertidos
# para string separada por espaços (ex.: "70 66 67 ..."), porque bash não
# suporta 0x00 dentro de strings comuns.
#
# Os ataques usam amostras reduzidas em relação às outras linguagens (bash é
# ordens de magnitude mais lento). FBC_ESCALA multiplica esses defaults:
#   FBC_ESCALA=10 bash bin/executar_testes.sh
FBC_ESCALA="${FBC_ESCALA:-1}"

# Inteiro aleatório em [min, max], inclusivo (random_int do PHP).
util_random_int() {
    local min=$1 max=$2
    local range=$(( max - min + 1 ))
    if [ "$range" -le 0 ]; then
        echo "$min"
        return
    fi
    echo $(( min + ((RANDOM * 32768 + RANDOM) % range) ))
}

# N bytes aleatórios no array (nameref) indicado.
util_random_bytes() {
    local -n _out=$1
    local n=$2
    _out=()
    local val
    while read -r val; do
        _out+=("$val")
    done < <(head -c "$n" /dev/urandom | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
}

# Popcount de um byte (0-255).
util_contar_bits() {
    local x=$1 count=0
    while [ "$x" -ne 0 ]; do
        count=$(( count + (x & 1) ))
        x=$(( x >> 1 ))
    done
    echo "$count"
}

# Quantos bits diferem entre duas strings de bytes decimais separados por espaço.
util_bits_diferentes() {
    local -a a=($1) b=($2)
    local i x diff=0
    for (( i = 0; i < ${#a[@]}; i++ )); do
        x=$(( a[i] ^ b[i] ))
        while [ "$x" -ne 0 ]; do
            diff=$(( diff + (x & 1) ))
            x=$(( x >> 1 ))
        done
    done
    echo "$diff"
}

# Embaralha um array (nameref) com Fisher-Yates.
util_shuffle() {
    local -n _arr=$1
    local i j tmp n=${#_arr[@]}
    for (( i = n - 1; i > 0; i-- )); do
        j=$(util_random_int 0 "$i")
        tmp=${_arr[i]}
        _arr[i]=${_arr[j]}
        _arr[j]=$tmp
    done
}

# Formata um número com N casas decimais (bash não tem float; usa awk).
# uso: util_fmt <casas> <valor>
util_fmt() {
    awk -v casas="$1" -v v="$2" 'BEGIN { printf "%.*f", casas, v }'
}

# Divisão em ponto flutuante: util_div <numerador> <denominador> [casas]
util_div() {
    awk -v n="$1" -v d="$2" -v casas="${3:-6}" 'BEGIN { if (d == 0) print 0; else printf "%.*f", casas, n / d }'
}

# Percentual: util_pct <numerador> <denominador> [casas]
util_pct() {
    awk -v n="$1" -v d="$2" -v casas="${3:-1}" 'BEGIN { if (d == 0) printf "%.*f", casas, 0; else printf "%.*f", casas, (n / d) * 100 }'
}

# Comparação em ponto flutuante: retorna 0 (true) se a < b.
util_menor() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'
}

# Comparação em ponto flutuante: retorna 0 (true) se a > b.
util_maior() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'
}
