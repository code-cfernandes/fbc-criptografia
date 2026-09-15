// Command fuzz_cruzado roda o fuzzing cruzado da implementação Go.
//
// Lê casos no formato chave|iv|proposito|plaintext (hex) e escreve uma linha
// indice|keystream|mac por caso, para comparação byte a byte com as outras
// linguagens do monorepo.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"criptografia/internal/seguranca"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "uso: fuzz_cruzado <casos.txt> <saida.txt>")
		os.Exit(2)
	}

	entrada, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer entrada.Close()

	saida, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer saida.Close()

	alvo := seguranca.NovoCriptografiaAlvo()

	leitor := bufio.NewScanner(entrada)
	leitor.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	escritor := bufio.NewWriter(saida)
	defer escritor.Flush()

	indice := 0
	for leitor.Scan() {
		linha := leitor.Text()
		if linha == "" {
			continue
		}

		partes := strings.Split(linha, "|")
		if len(partes) != 4 {
			fmt.Fprintf(os.Stderr, "caso %d malformado: %s\n", indice, linha)
			os.Exit(1)
		}

		chave, err := hex.DecodeString(partes[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "caso %d: chave inválida: %v\n", indice, err)
			os.Exit(1)
		}
		iv, err := hex.DecodeString(partes[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "caso %d: iv inválido: %v\n", indice, err)
			os.Exit(1)
		}
		plaintext, err := hex.DecodeString(partes[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "caso %d: plaintext inválido: %v\n", indice, err)
			os.Exit(1)
		}

		keystream := alvo.GerarKeystreamBruto(chave, iv, partes[2], len(plaintext))
		mac := alvo.ChecksumBruto(plaintext, chave)

		fmt.Fprintf(escritor, "%d|%s|%s\n", indice, hex.EncodeToString(keystream), hex.EncodeToString(mac))
		indice++
	}

	if err := leitor.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
