#!/usr/bin/env bash
# Harness de regressão histórica (porte do regressao.js do Node).
#
# Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
# bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
# (ATQ_VULNERAVEL=1). Em seguida o mesmo ataque roda contra o código atual e
# PRECISA resistir (ATQ_VULNERAVEL=0).
#
# Adaptação bash: sem classes/objetos, o "alvo" é um conjunto de funções
# alvo_*. O snapshot implementa snapshot_* com as mutações e os alvo_* passam
# a despachar para elas enquanto ALVO_MODO="snapshot". Dados binários
# circulam como arrays de decimais (0-255), nunca como strings.

cd "$(dirname "$0")/../.." || exit 1

source src/Core/Criptografia.sh
source src/Seguranca/ResultadoAtaque.sh
source src/Seguranca/Util.sh
source src/Seguranca/CriptografiaAlvo.sh

ATAQUES_REGRESSAO=(
    AtaqueCorrelacaoMesmoPlaintext
    AtaqueFoldEstrutural
    AtaqueAvalancheChecksum
    AtaqueIntegral
    AtaqueSeparacaoChaveIV
    AtaqueCanonicalizacaoToken
)
for ataque in "${ATAQUES_REGRESSAO[@]}"; do
    # shellcheck source=/dev/null
    source "src/Seguranca/Ataques/$ataque.sh"
done

alvo_init

# ---------------------------------------------------------------------------
# Snapshot: funções equivalentes às gerar_keystream/checksum/decode reais,
# porém com as mutações que reintroduzem cada bug histórico.
# ---------------------------------------------------------------------------

# snapshot_gerar_keystream <nome_saida> <key> <iv> <proposito> <tamanho>
# Mutações: bug 1 (ignora IV), bug 2 (combinador simétrico + distância 16),
#           bug 4 (apenas [3]), bug 5 (passo sem reinserir a chave).
snapshot_gerar_keystream() {
    local -n _saida=$1
    local -a key=($2)
    local -a iv=($3)
    local -a prop=($4)
    local tamanho=$5
    local bug=$SNAPSHOT_BUG

    # bug 1: keystream ignora o IV (mesmo fluxo para o mesmo plaintext).
    if [ "$bug" -eq 1 ]; then
        local -a iv_zero=()
        local z
        for (( z = 0; z < ${#iv[@]}; z++ )); do
            iv_zero+=(0)
        done
        iv=("${iv_zero[@]}")
    fi

    # bug 2: distâncias incluem exatamente a metade do bloco (16).
    # bug 4: uma única distância [3].
    local -a distancias
    if [ "$bug" -eq 4 ]; then
        distancias=(3)
    elif [ "$bug" -eq 2 ]; then
        distancias=(3 5 11 19 41 16)
    else
        distancias=("${DISTANCIAS_DIFUSAO[@]}")
    fi

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
    local dist idx d n soma pf apos bpos nb rot x

    while [ ${#_saida[@]} -lt "$tamanho" ]; do
        for dist in "${distancias[@]}"; do
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
                # bug 5: não reinsere a chave em cada rodada.
                if [ "$bug" -ne 5 ]; then
                    soma=$(( soma ^ key[(pf + round_idx) % key_len] ))
                fi
                soma=$(( (soma * 131) & 0xFF ))
                a[pos]=$bpos
                novo_b[pos]=$soma
            done

            for (( pos = 0; pos < bloco; pos++ )); do
                nb=${novo_b[pos]}
                if [ "$bug" -eq 2 ]; then
                    # bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
                    x=$(( nb ^ novo_b[(pos + dist) % bloco] ))
                    misturado[pos]=$(( ((x << 1) | (x >> 7)) & 0xFF ))
                else
                    rot=$(( ((nb << 1) | (nb >> 7)) & 0xFF ))
                    misturado[pos]=$(( rot ^ novo_b[(pos + dist) % bloco] ))
                fi
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

# snapshot_checksum <nome_saida> <dados> <key>
# Mutação: bug 3 remove a finalização (as 3 rodadas de avalanche).
snapshot_checksum() {
    local -n _saida=$1
    local -a dados=($2)
    local -a key=($3)
    local bug=$SNAPSHOT_BUG

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
        # bug 3: sem finalização.
        if [ "$bug" -ne 3 ]; then
            for (( k = 0; k < 3; k++ )); do
                acumulador=$(( (acumulador ^ (acumulador >> 16)) & 0xFFFFFFFF ))
                acumulador=$(( (acumulador * 16777619) & 0xFFFFFFFF ))
                acumulador=$(( ((acumulador << 13) | (acumulador >> 19)) & 0xFFFFFFFF ))
            done
        fi
        _saida+=( $(( (acumulador >> 24) & 0xFF )) $(( (acumulador >> 16) & 0xFF )) $(( (acumulador >> 8) & 0xFF )) $(( acumulador & 0xFF )) )
    done
}

# snapshot_base64url_decode <nome_saida> <data>
# Mutação: bug 6 aceita alfabeto padrão e lixo (decoder frouxo).
snapshot_base64url_decode() {
    local -n _out=$1
    local data=$2
    if [ "$SNAPSHOT_BUG" -ne 6 ]; then
        base64url_decode_to_array _out "$data"
        return
    fi

    local s=${data//-/+}
    s=${s//_//}
    s=$(printf '%s' "$s" | tr -cd 'A-Za-z0-9+/=')
    local mod=$(( ${#s} % 4 ))
    if [ "$mod" -ne 0 ]; then
        s+=$(printf '=%.0s' $(seq 1 $(( 4 - mod ))))
    fi

    _out=()
    local val
    while read -r val; do
        _out+=("$val")
    done < <(printf '%s' "$s" | base64 -d | od -An -v -tu1 | tr -s ' ' '\n' | sed '/^$/d')
}

# snapshot_encrypt / snapshot_decrypt: mesmos fluxos dos reais, mas usando os
# geradores mutados do snapshot (espelha o SnapshotAlvo do Node).
snapshot_encrypt() {
    local texto=$1
    local -a key iv texto_bytes
    get_key_bytes key
    bytes_from_stdin iv < <(head -c 16 /dev/urandom)
    string_to_bytes texto_bytes "$texto"

    local -a enc_keystream ciphertext mac_key iv_mais_ct integridade payload
    snapshot_gerar_keystream enc_keystream "${key[*]}" "${iv[*]}" "101 110 99" "${#texto_bytes[@]}"
    xor_bytes ciphertext "${texto_bytes[*]}" "${enc_keystream[*]}"

    snapshot_gerar_keystream mac_key "${key[*]}" "${iv[*]}" "109 97 99" "$TAM_BLOCO"
    iv_mais_ct=("${iv[@]}" "${ciphertext[@]}")
    snapshot_checksum integridade "${iv_mais_ct[*]}" "${mac_key[*]}"

    payload=("${integridade[@]}" "${ciphertext[@]}" "${iv[@]}")
    printf 'FBC%s' "$(bytes_to_stdout "${payload[@]}" | base64url_encode_stdin)"
    echo
}

snapshot_decrypt() {
    local token=$1
    if [ "${token:0:3}" != "FBC" ]; then
        echo "Erro: token inválido, precisa começar com FBC." >&2
        exit 1
    fi

    local -a key decoded
    get_key_bytes key
    snapshot_base64url_decode decoded "${token:3}" || exit 1

    local total=${#decoded[@]}
    local -a integridade_recebida=("${decoded[@]:0:$TAM_BLOCO}")
    local -a iv=("${decoded[@]: -16}")
    local ct_len=$(( total - TAM_BLOCO - 16 ))
    local -a ciphertext=("${decoded[@]:$TAM_BLOCO:$ct_len}")

    local -a mac_key iv_mais_ct integridade_esperada
    snapshot_gerar_keystream mac_key "${key[*]}" "${iv[*]}" "109 97 99" "$TAM_BLOCO"
    iv_mais_ct=("${iv[@]}" "${ciphertext[@]}")
    snapshot_checksum integridade_esperada "${iv_mais_ct[*]}" "${mac_key[*]}"

    if [ "${integridade_esperada[*]}" != "${integridade_recebida[*]}" ]; then
        echo "Erro: token adulterado ou chave incorreta." >&2
        exit 1
    fi

    local -a enc_keystream plaintext_bytes
    snapshot_gerar_keystream enc_keystream "${key[*]}" "${iv[*]}" "101 110 99" "$ct_len"
    xor_bytes plaintext_bytes "${ciphertext[*]}" "${enc_keystream[*]}"

    bytes_to_stdout "${plaintext_bytes[@]}"
    echo
}

# ---------------------------------------------------------------------------
# Despacho: os ataques chamam alvo_*; alternamos entre real e snapshot.
# ---------------------------------------------------------------------------
ALVO_MODO="real"
SNAPSHOT_BUG=0

alvo_ativar_real() {
    ALVO_MODO="real"
    SNAPSHOT_BUG=0
}

alvo_ativar_snapshot() {
    ALVO_MODO="snapshot"
    SNAPSHOT_BUG=$1
}

alvo_encrypt() {
    if [ "$ALVO_MODO" = "snapshot" ]; then
        snapshot_encrypt "$1"
    else
        cripto_encrypt "$1"
    fi
}

alvo_decrypt() {
    if [ "$ALVO_MODO" = "snapshot" ]; then
        snapshot_decrypt "$1"
    else
        cripto_decrypt "$1"
    fi
}

# Nota: o nameref local usa nome diferente (_alvo_ref) dos namerefs internos
# das funções chamadas (_saida/_out/_saida_dec) para evitar "circular name
# reference" ao encadear namerefs.
alvo_gerar_keystream_bruto() {
    local -n _alvo_ref=$1
    if [ "$ALVO_MODO" = "snapshot" ]; then
        snapshot_gerar_keystream _alvo_ref "$2" "$3" "$4" "$5"
    else
        gerar_keystream _alvo_ref "$2" "$3" "$4" "$5"
    fi
}

alvo_checksum_bruto() {
    local -n _alvo_ref=$1
    if [ "$ALVO_MODO" = "snapshot" ]; then
        snapshot_checksum _alvo_ref "$2" "$3"
    else
        checksum _alvo_ref "$2" "$3"
    fi
}

alvo_base64url_decode() {
    local -n _alvo_ref=$1
    if [ "$ALVO_MODO" = "snapshot" ]; then
        snapshot_base64url_decode _alvo_ref "$2"
    else
        base64url_decode_to_array _alvo_ref "$2"
    fi
}

# ---------------------------------------------------------------------------
# Item 7 (específico do bash): regressão de NUL.
#
# O bug histórico guardava bytes decodificados numa variável string comum,
# truncando no 0x00. O decode correto devolve um array de decimais; o teste
# falha se o NUL for perdido.
# ---------------------------------------------------------------------------
teste_regressao_nul() {
    local -a originais=(0 1 0 255 0 66 0 200)
    local corpo
    corpo=$(bytes_to_stdout "${originais[@]}" | base64url_encode_stdin)

    local -a decodificados
    if ! base64url_decode_to_array decodificados "$corpo"; then
        echo "  ❌ NUL: falha ao decodificar o corpo base64url."
        return 1
    fi

    if [ "${decodificados[*]}" != "${originais[*]}" ]; then
        echo "  ❌ NUL: bytes divergiram (esperado '${originais[*]}', obtido '${decodificados[*]}')."
        return 1
    fi

    local zeros=0 b
    for b in "${decodificados[@]}"; do
        if [ "$b" -eq 0 ]; then
            zeros=$(( zeros + 1 ))
        fi
    done
    if [ "$zeros" -lt 1 ]; then
        echo "  ❌ NUL: nenhum byte 0x00 sobreviveu ao decode."
        return 1
    fi

    # Demonstra o bug histórico: uma string comum perde os NULs (o aviso de
    # "ignored null byte" é justamente o sintoma que queremos capturar).
    local string_ruim
    { string_ruim=$(bytes_to_stdout "${originais[@]}"); } 2>/dev/null
    if [ "${#string_ruim}" -eq "${#originais[@]}" ]; then
        echo "  ❌ NUL: o cenário histórico não truncou; o teste não teria valor."
        return 1
    fi

    echo "  ✅ NUL: ${#decodificados[@]} bytes preservados (${zeros} byte(s) 0x00 intactos); string comum reteria apenas ${#string_ruim}."
    return 0
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
resetar_resultado() {
    ATQ_NOME=""
    ATQ_VULNERAVEL=0
    ATQ_SEVERIDADE="info"
    ATQ_DETALHES=""
    ATQ_SKIP=0
    ATQ_ERRO=0
}

DESCRICOES=(
    "keystream ignora o IV"
    "combinador simétrico (metades colapsam)"
    "checksum sem finalização"
    "cinco rodadas de difusão"
    "chave só no estado inicial"
    "base64 não estrito"
)

echo "========================================================================"
echo "REGRESSÃO HISTÓRICA"
echo "========================================================================"

falhas=0
for idx in 0 1 2 3 4 5; do
    bug=$(( idx + 1 ))
    descricao=${DESCRICOES[idx]}
    ataque=${ATAQUES_REGRESSAO[idx]}

    alvo_ativar_snapshot "$bug"
    resetar_resultado
    "$ataque" >/dev/null 2>&1
    snap_vuln=$ATQ_VULNERAVEL
    snap_resumo="$ATQ_DETALHES"

    alvo_ativar_real
    resetar_resultado
    "$ataque" >/dev/null 2>&1
    real_vuln=$ATQ_VULNERAVEL
    real_resumo="$ATQ_DETALHES"

    detectou=0
    resistiu=0
    [ "$snap_vuln" -eq 1 ] && detectou=1
    [ "$real_vuln" -eq 0 ] && resistiu=1

    ok=0
    if [ "$detectou" -eq 1 ] && [ "$resistiu" -eq 1 ]; then
        ok=1
    else
        falhas=$(( falhas + 1 ))
    fi

    if [ "$ok" -eq 1 ]; then
        echo "  ✅ bug $bug ($descricao): snapshot detectado | atual resistiu"
    else
        echo "  ❌ bug $bug ($descricao): snapshot $([ "$detectou" -eq 1 ] && echo detectado || echo 'NÃO detectado') | atual $([ "$resistiu" -eq 1 ] && echo resistiu || echo 'ACUSOU')"
        echo "       snapshot: $snap_resumo"
        echo "       atual:    $real_resumo"
    fi
done

if ! teste_regressao_nul; then
    falhas=$(( falhas + 1 ))
fi

echo "========================================================================"
if [ "$falhas" -eq 0 ]; then
    echo "RESUMO: 6 bugs históricos detectados; código atual resiste a todos; NUL preservado."
else
    echo "RESUMO: $falhas caso(s) falharam."
fi
echo "========================================================================"

exit $([ "$falhas" -eq 0 ] && echo 0 || echo 1)
