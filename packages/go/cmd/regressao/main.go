// Harness de regressão histórica (porte de
// packages/node/tests/regressao_historica/regressao.js).
//
// Prova que a suíte ainda detecta os bugs reais que já corrigimos: para cada
// bug, um snapshot reintroduz a falha e o ataque pareado PRECISA acusá-la
// (Vulneravel=true). Em seguida o mesmo ataque roda contra o código atual e
// PRECISA resistir (Vulneravel=false).
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"criptografia/internal/core"
	"criptografia/internal/seguranca"
	"criptografia/internal/seguranca/ataques"
)

const (
	tamBloco  = 32
	digitosPi = "31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"
)

func rotacaoDoRound(roundIdx int) int {
	d := int(digitosPi[roundIdx%len(digitosPi)] - '0')
	return (d % 7) + 1
}

// passoComBug: bug 5 remove a reinserção da chave em cada rodada.
func passoComBug(bug int, a, b byte, keyBuf, propositoBuf []byte, posFib, roundIdx int) (byte, byte) {
	n := rotacaoDoRound(roundIdx)

	soma := a + b
	soma = core.RotEsquerda8(soma, n)
	soma ^= propositoBuf[posFib%len(propositoBuf)]
	if bug != 5 {
		soma ^= keyBuf[(posFib+roundIdx)%len(keyBuf)]
	}
	soma = soma * 131

	return b, soma
}

// gerarKeystreamComBug: bugs 1, 2, 4, 5.
func gerarKeystreamComBug(bug int, keyBuf, ivBuf []byte, proposito string, tamanho int) []byte {
	if bug == 1 {
		// bug 1: keystream ignora o IV (vaza o mesmo fluxo para o mesmo plaintext).
		return core.GerarKeystream(keyBuf, make([]byte, len(ivBuf)), proposito, tamanho)
	}

	bloco := tamBloco
	// bug 2: o colapso de metades só acontece quando a distância é exatamente
	// metade do bloco (16) — reproduzimos a condição histórica.
	var distancias []int
	switch bug {
	case 4:
		distancias = []int{3}
	case 2:
		distancias = []int{3, 5, 11, 19, 41, 16}
	default:
		distancias = []int{3, 5, 11, 19, 41, 3, 5, 11, 19, 41}
	}
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
		for _, dist := range distancias {
			novoB := make([]byte, bloco)
			for pos := 0; pos < bloco; pos++ {
				novoA, novoBb := passoComBug(bug, a[pos], b[pos], keyBuf, propositoBuf, posFibBase+pos, roundIdx)
				a[pos] = novoA
				novoB[pos] = novoBb
			}
			misturado := make([]byte, bloco)
			for pos := 0; pos < bloco; pos++ {
				vizinho := novoB[(pos+dist)%bloco]
				if bug == 2 {
					// bug 2: combinador SIMÉTRICO (colapsa metades do bloco).
					misturado[pos] = core.RotEsquerda8(novoB[pos]^vizinho, 1)
				} else {
					misturado[pos] = core.RotEsquerda8(novoB[pos], 1) ^ vizinho
				}
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

// checksumComBug: bug 3 remove a finalização.
func checksumComBug(bug int, dadosBuf, keyBuf []byte) []byte {
	saida := make([]byte, 32)
	keyLen := len(keyBuf)

	for rodada := 0; rodada < 8; rodada++ {
		acumulador := uint32(0x811c9dc5) ^ (uint32(rodada) * uint32(0x01000193))

		for i := 0; i < len(dadosBuf); i++ {
			b := dadosBuf[i] ^ keyBuf[(i+rodada)%keyLen]
			acumulador = acumulador ^ uint32(b)
			acumulador = acumulador * 16777619
			acumulador = core.RotEsquerda32(acumulador, (i%13)+1)
		}

		if bug != 3 {
			for k := 0; k < 3; k++ {
				acumulador = acumulador ^ (acumulador >> 16)
				acumulador = acumulador * 16777619
				acumulador = core.RotEsquerda32(acumulador, 13)
			}
		}

		saida[rodada*4+0] = byte(acumulador >> 24)
		saida[rodada*4+1] = byte(acumulador >> 16)
		saida[rodada*4+2] = byte(acumulador >> 8)
		saida[rodada*4+3] = byte(acumulador)
	}

	return saida
}

// base64urlDecodeComBug: bug 6 aceita alfabeto padrão e lixo.
func base64urlDecodeComBug(bug int, str string) ([]byte, error) {
	if bug != 6 {
		return core.Base64urlDecode(str)
	}

	var sb strings.Builder
	for i := 0; i < len(str); i++ {
		c := str[i]
		switch {
		case c == '-':
			sb.WriteByte('+')
		case c == '_':
			sb.WriteByte('/')
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=':
			sb.WriteByte(c)
		}
	}
	s := sb.String()
	if mod := len(s) % 4; mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}
	return base64.StdEncoding.DecodeString(s)
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

// SnapshotAlvo aponta para a cifra com o bug selecionado.
type SnapshotAlvo struct {
	*seguranca.CriptografiaAlvo
	bug int
}

// NovoSnapshotAlvo cria um alvo com o bug indicado.
func NovoSnapshotAlvo(bug int) *SnapshotAlvo {
	return &SnapshotAlvo{CriptografiaAlvo: seguranca.NovoCriptografiaAlvo(), bug: bug}
}

// GerarKeystreamBruto usa a keystream com o bug selecionado.
func (s *SnapshotAlvo) GerarKeystreamBruto(key, iv []byte, proposito string, tamanho int) []byte {
	return gerarKeystreamComBug(s.bug, key, iv, proposito, tamanho)
}

// ChecksumBruto usa o checksum com o bug selecionado.
func (s *SnapshotAlvo) ChecksumBruto(dados, key []byte) []byte {
	return checksumComBug(s.bug, dados, key)
}

// Base64urlDecode usa o decoder com o bug selecionado.
func (s *SnapshotAlvo) Base64urlDecode(data string) ([]byte, error) {
	return base64urlDecodeComBug(s.bug, data)
}

// Encrypt cifra usando as camadas com bug.
func (s *SnapshotAlvo) Encrypt(texto []byte) (string, error) {
	key := []byte(s.ChaveDeTeste())
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	ks := s.GerarKeystreamBruto(key, iv, "enc", len(texto))
	ct := make([]byte, len(texto))
	for i := range texto {
		ct[i] = texto[i] ^ ks[i]
	}

	macKey := s.GerarKeystreamBruto(key, iv, "mac", tamBloco)
	integridade := s.ChecksumBruto(concat(iv, ct), macKey)

	return "FBC" + core.Base64urlEncode(concat(integridade, ct, iv)), nil
}

// Decrypt decifra usando as camadas com bug.
func (s *SnapshotAlvo) Decrypt(token string) (string, error) {
	if len(token) < 3 || token[:3] != "FBC" {
		return "", errors.New("prefixo")
	}
	key := []byte(s.ChaveDeTeste())
	decoded, err := s.Base64urlDecode(token[3:])
	if err != nil {
		return "", err
	}

	integ := decoded[:tamBloco]
	iv := decoded[len(decoded)-16:]
	ct := decoded[tamBloco : len(decoded)-16]

	macKey := s.GerarKeystreamBruto(key, iv, "mac", tamBloco)
	esperado := s.ChecksumBruto(concat(iv, ct), macKey)
	if !bytes.Equal(esperado, integ) {
		return "", errors.New("MAC")
	}

	ks := s.GerarKeystreamBruto(key, iv, "enc", len(ct))
	out := make([]byte, len(ct))
	for i := range ct {
		out[i] = ct[i] ^ ks[i]
	}
	return string(out), nil
}

type caso struct {
	bug       int
	descricao string
	ataque    seguranca.Ataque
}

var casos = []caso{
	{bug: 1, descricao: "keystream ignora o IV", ataque: ataques.NovoAtaqueCorrelacaoMesmoPlaintext()},
	{bug: 2, descricao: "combinador simétrico (metades colapsam)", ataque: ataques.NovoAtaqueFoldEstrutural()},
	{bug: 3, descricao: "checksum sem finalização", ataque: ataques.NovoAtaqueAvalancheChecksum()},
	{bug: 4, descricao: "cinco rodadas de difusão", ataque: ataques.NovoAtaqueIntegral()},
	{bug: 5, descricao: "chave só no estado inicial", ataque: ataques.NovoAtaqueSeparacaoChaveIV()},
	{bug: 6, descricao: "base64 não estrito", ataque: &ataques.AtaqueCanonicalizacaoToken{}},
}

func main() {
	fmt.Println(strings.Repeat("=", 72))
	fmt.Println("REGRESSÃO HISTÓRICA")
	fmt.Println(strings.Repeat("=", 72))

	falhas := 0
	for _, c := range casos {
		snapshot := NovoSnapshotAlvo(c.bug)
		real := seguranca.NovoCriptografiaAlvo()

		rSnapshot, errSnapshot := c.ataque.Executar(snapshot)
		rReal, errReal := c.ataque.Executar(real)
		if errSnapshot != nil || errReal != nil {
			msg := ""
			if errSnapshot != nil {
				msg = errSnapshot.Error()
			} else {
				msg = errReal.Error()
			}
			fmt.Printf("  ❌ bug %d (%s): erro — %s\n", c.bug, c.descricao, msg)
			falhas++
			continue
		}

		detectou := rSnapshot.Vulneravel
		resistiu := !rReal.Vulneravel
		ok := detectou && resistiu
		if !ok {
			falhas++
		}

		statusSnapshot := "NÃO detectado"
		if detectou {
			statusSnapshot = "detectado"
		}
		statusAtual := "ACUSOU"
		if resistiu {
			statusAtual = "resistiu"
		}

		marca := "❌"
		if ok {
			marca = "✅"
		}
		fmt.Printf("  %s bug %d (%s): snapshot %s | atual %s\n",
			marca, c.bug, c.descricao, statusSnapshot, statusAtual)

		if !ok {
			fmt.Printf("       snapshot: %s\n", rSnapshot.LinhaResumo())
			fmt.Printf("       atual:    %s\n", rReal.LinhaResumo())
		}
	}

	fmt.Println(strings.Repeat("=", 72))
	if falhas == 0 {
		fmt.Printf("RESUMO: %d bugs históricos detectados; código atual resiste a todos.\n", len(casos))
	} else {
		fmt.Printf("RESUMO: %d caso(s) falharam.\n", falhas)
	}
	fmt.Println(strings.Repeat("=", 72))

	if falhas != 0 {
		os.Exit(1)
	}
}
