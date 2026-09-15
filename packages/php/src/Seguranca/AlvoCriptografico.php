<?php

namespace Application\Seguranca;

/**
 * Contrato que uma cifra precisa cumprir pra ser testada pela suíte de ataques.
 *
 * Os métodos "obrigatórios" (encrypt/decrypt) bastam pros ataques de alto nível
 * (ida-e-volta, adulteração, colisão de IV, bytes fixos entre tokens).
 *
 * O método `gerarKeystreamBruto` é OPCIONAL - retorne null se a cifra não expuser
 * essa camada. Sem ele, os ataques de baixo nível (avalanche, distribuição,
 * cobertura de dependência, fold estrutural) são pulados automaticamente.
 */
interface AlvoCriptografico
{
    public function encrypt(string $texto): string;

    public function decrypt(string $token): string;

    /** Prefixo esperado no início de um token válido (ex: "FBC"). */
    public function prefixo(): string;

    /**
     * Decompõe um token (já sem prefixo e já base64url-decodificado) nos
     * campos que o compõem. Formato esperado das chaves: 'integridade',
     * 'ciphertext', 'iv' - cada uma como string binária.
     */
    public function decompor(string $token): array;

    /**
     * Recompõe um token a partir dos campos (inverso de decompor()).
     */
    public function recompor(array $campos): string;

    /**
     * Gera N bytes de keystream bruto a partir de key+iv+propósito, se a
     * cifra expuser essa camada internamente (via Reflection, por exemplo).
     * Retorne null se não for aplicável - os testes de baixo nível serão
     * pulados sem quebrar a suíte.
     */
    public function gerarKeystreamBruto(string $key, string $iv, string $proposito, int $tamanho): ?string;

    /**
     * Chama o checksum() interno diretamente, se a cifra expuser essa
     * camada (via Reflection, por exemplo). Retorne null se não for
     * aplicável - os testes de colisão de MAC serão pulados.
     */
    public function checksumBruto(string $dados, string $key): ?string;

    /** Uma chave válida pra usar nos testes. */
    public function chaveDeTeste(): string;

    /** Tamanho do IV em bytes (usado pelos ataques que manipulam o IV diretamente). */
    public function tamanhoIv(): int;
}
