// Package core implementa a cifra caseira educacional FBC.
//
// Estrutura do token: FBC + base64url( integridade[32] . ciphertext[n] . iv[16] )
//
// Porte fiel de packages/typescript/src/Core/Criptografia.ts. Qualquer mudança
// de comportamento aqui quebraria a compatibilidade byte a byte com as outras
// linguagens do monorepo.
package core

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
)

// TamBloco é o tamanho do bloco usado na geração do keystream.
const TamBloco = 32

// Mesmas distâncias da versão PHP (Fibonacci -> N-ésimo primo, pulando o 2),
// dobradas para combater o ataque integral.
var distanciasDifusao = [10]int{3, 5, 11, 19, 41, 3, 5, 11, 19, 41}

const digitosPi = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"

// RotEsquerda8 rotaciona um byte à esquerda em n bits.
func RotEsquerda8(b byte, n int) byte {
	n &= 7
	if n == 0 {
		return b
	}
	return (b << n) | (b >> (8 - n))
}

// RotEsquerda32 rotaciona um uint32 à esquerda em n bits.
func RotEsquerda32(val uint32, n int) uint32 {
	n &= 31
	if n == 0 {
		return val
	}
	return (val << n) | (val >> (32 - n))
}

func rotacaoDoRound(roundIdx int) int {
	d := int(digitosPi[roundIdx%len(digitosPi)] - '0')
	return (d % 7) + 1
}

// passo é um passo da recorrência tipo-Fibonacci para uma posição do bloco.
func passo(a, b byte, keyBuf, propositoBuf []byte, posFib, roundIdx int) (byte, byte) {
	n := rotacaoDoRound(roundIdx)

	soma := a + b
	soma = RotEsquerda8(soma, n)
	soma ^= propositoBuf[posFib%len(propositoBuf)]
	soma ^= keyBuf[(posFib+roundIdx)%len(keyBuf)]
	soma = soma * 131

	return b, soma
}

// GerarKeystream gera tamanho bytes de keystream a partir de key + IV + propósito.
func GerarKeystream(keyBuf, ivBuf []byte, proposito string, tamanho int) []byte {
	bloco := TamBloco
	ivLen := len(ivBuf)
	keyLen := len(keyBuf)
	propositoBuf := []byte(proposito)

	a := make([]byte, bloco)
	b := make([]byte, bloco)
	for pos := 0; pos < bloco; pos++ {
		a[pos] = keyBuf[pos%keyLen] ^ ivBuf[pos%ivLen]
		b[pos] = keyBuf[(pos+1)%keyLen] ^ ivBuf[(pos+1)%ivLen]
	}

	partes := make([]byte, 0)
	totalGerado := 0
	roundIdx := 0
	posFibBase := 0

	for totalGerado < tamanho {
		for _, dist := range distanciasDifusao {
			novoB := make([]byte, bloco)
			for pos := 0; pos < bloco; pos++ {
				novoA, novoBb := passo(a[pos], b[pos], keyBuf, propositoBuf, posFibBase+pos, roundIdx)
				a[pos] = novoA
				novoB[pos] = novoBb
			}

			misturado := make([]byte, bloco)
			for pos := 0; pos < bloco; pos++ {
				vizinho := novoB[(pos+dist)%bloco]
				misturado[pos] = RotEsquerda8(novoB[pos], 1) ^ vizinho
			}
			b = misturado
			roundIdx++
		}

		posFibBase += bloco
		partes = append(partes, b...)
		totalGerado += bloco
	}

	if tamanho < len(partes) {
		return partes[:tamanho]
	}
	return partes
}

// Checksum é o "MAC" caseiro: 8 rodadas de um checksum estilo FNV.
func Checksum(dadosBuf, keyBuf []byte) []byte {
	saida := make([]byte, 32)

	for rodada := 0; rodada < 8; rodada++ {
		acumulador := uint32(0x811c9dc5) ^ (uint32(rodada) * uint32(0x01000193))
		keyLen := len(keyBuf)
		length := len(dadosBuf)

		for i := 0; i < length; i++ {
			b := dadosBuf[i] ^ keyBuf[(i+rodada)%keyLen]
			acumulador = acumulador ^ uint32(b)
			acumulador = acumulador * 16777619
			acumulador = RotEsquerda32(acumulador, (i%13)+1)
		}

		for k := 0; k < 3; k++ {
			acumulador = acumulador ^ (acumulador >> 16)
			acumulador = acumulador * 16777619
			acumulador = RotEsquerda32(acumulador, 13)
		}

		saida[rodada*4+0] = byte(acumulador >> 24)
		saida[rodada*4+1] = byte(acumulador >> 16)
		saida[rodada*4+2] = byte(acumulador >> 8)
		saida[rodada*4+3] = byte(acumulador)
	}

	return saida
}

func xorBytes(dadosBuf, keystreamBuf []byte) []byte {
	out := make([]byte, len(dadosBuf))
	for i := range dadosBuf {
		out[i] = dadosBuf[i] ^ keystreamBuf[i]
	}
	return out
}

func concat(partes ...[]byte) []byte {
	total := 0
	for _, p := range partes {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range partes {
		out = append(out, p...)
	}
	return out
}

// Base64urlEncode codifica em base64url sem padding.
func Base64urlEncode(buf []byte) string {
	return base64.RawURLEncoding.EncodeToString(buf)
}

// Base64urlDecode decodifica base64url sem padding e valida a canonicidade.
func Base64urlDecode(str string) ([]byte, error) {
	if str != "" {
		for i := 0; i < len(str); i++ {
			c := str[i]
			valido := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_'
			if !valido {
				return nil, errors.New("Token contém caracteres inválidos.")
			}
		}
	}

	if len(str)%4 == 1 {
		return nil, errors.New("Comprimento de token inválido.")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	if Base64urlEncode(decoded) != str {
		return nil, errors.New("Token não está em forma canônica.")
	}

	return decoded, nil
}

func getKey() ([]byte, error) {
	key := os.Getenv("FBC_KEY")
	if len(key) != 32 {
		return nil, errors.New("Chave deve ter 32 bytes.")
	}
	return []byte(key), nil
}

// Encrypt cifra texto e devolve um token FBC.
func Encrypt(texto []byte) (string, error) {
	key, err := getKey()
	if err != nil {
		return "", err
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	textBuf := make([]byte, len(texto))
	copy(textBuf, texto)

	encKeystream := GerarKeystream(key, iv, "enc", len(textBuf))
	ciphertext := xorBytes(textBuf, encKeystream)

	macKey := GerarKeystream(key, iv, "mac", TamBloco)
	integridade := Checksum(concat(iv, ciphertext), macKey)

	return "FBC" + Base64urlEncode(concat(integridade, ciphertext, iv)), nil
}

// Decrypt decifra um token FBC.
func Decrypt(token string) (string, error) {
	if len(token) < 3 || token[:3] != "FBC" {
		return "", errors.New("Invalid text. Text must start with FBC.")
	}

	key, err := getKey()
	if err != nil {
		return "", err
	}

	decoded, err := Base64urlDecode(token[3:])
	if err != nil {
		return "", err
	}

	if len(decoded) < TamBloco+16 {
		return "", errors.New("Token adulterado ou chave incorreta.")
	}

	integridadeRecebida := decoded[:TamBloco]
	iv := decoded[len(decoded)-16:]
	ciphertext := decoded[TamBloco : len(decoded)-16]

	macKey := GerarKeystream(key, iv, "mac", TamBloco)
	integridadeEsperada := Checksum(concat(iv, ciphertext), macKey)

	if subtle.ConstantTimeCompare(integridadeEsperada, integridadeRecebida) != 1 {
		return "", errors.New("Token adulterado ou chave incorreta.")
	}

	encKeystream := GerarKeystream(key, iv, "enc", len(ciphertext))
	return string(xorBytes(ciphertext, encKeystream)), nil
}
