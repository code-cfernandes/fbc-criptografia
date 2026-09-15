# A chave precisa ter exatamente 32 bytes. Chaves de tamanho errado devem ser
# rejeitadas (não silenciosamente truncadas/preenchidas), e uma chave de 32
# bytes válida deve funcionar. Uma validação frouxa aqui vira uma chave mais
# curta (e mais fraca) na prática.
#
# Adaptação bash: em vez de instanciar um novo CriptografiaAlvo, troca a
# global de ambiente FBC_KEY e restaura a chave original no final (mesmo se
# algo falhar, o restore fica no caminho normal - os comandos abaixo não
# disparam `set -e`).
AtaqueValidacaoChave() {
    ATQ_NOME="Validação do tamanho da chave"

    local -a tamanhos=(0 1 16 31 33 64)
    local chaveOriginal
    chaveOriginal="$(alvo_chave_de_teste)"

    local aceitas="" validaRejeitada=0
    local len chave token

    for len in "${tamanhos[@]}"; do
        if [ "$len" -eq 0 ]; then
            chave=""
        else
            chave=$(printf 'K%.0s' $(seq 1 "$len"))
        fi
        export FBC_KEY="$chave"
        # Encrypt com chave de tamanho inválido DEVE falhar.
        if token=$(alvo_encrypt 'x' 2>/dev/null); then
            aceitas+="$len, "
        fi
    done

    chave=$(printf 'K%.0s' $(seq 1 32))
    export FBC_KEY="$chave"
    if ! token=$(alvo_encrypt 'x' 2>/dev/null); then
        validaRejeitada=1
    fi

    # Restaura a chave original do alvo.
    export FBC_KEY="$chaveOriginal"

    if [ -n "$aceitas" ] || [ "$validaRejeitada" -eq 1 ]; then
        local detalhes=""
        if [ -n "$aceitas" ]; then
            detalhes+="chaves de tamanho inválido aceitas: ${aceitas%, }"
        fi
        if [ "$validaRejeitada" -eq 1 ]; then
            [ -n "$detalhes" ] && detalhes+="; "
            detalhes+="chave válida de 32 bytes foi rejeitada"
        fi
        res_vulneravel "$detalhes" "alta"
    else
        res_resistiu "Tamanhos inválidos rejeitados e chave de 32 bytes aceita"
    fi
    return 0
}
