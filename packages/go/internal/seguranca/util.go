package seguranca

import (
	crand "crypto/rand"
	"encoding/binary"
)

// RandomInt devolve um inteiro aleatório em [min, max], inclusivo.
func RandomInt(min, max int) int {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err)
	}
	return min + int(binary.BigEndian.Uint64(b[:])%uint64(max-min+1))
}

// RandomBytes devolve n bytes aleatórios.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ContarBits1 faz o popcount de um byte (0-255).
func ContarBits1(b byte) int {
	count := 0
	for x := b; x != 0; x >>= 1 {
		count += int(x & 1)
	}
	return count
}

// ContarBitsBuffer faz o popcount total de um buffer.
func ContarBitsBuffer(buf []byte) int {
	total := 0
	for _, b := range buf {
		total += ContarBits1(b)
	}
	return total
}

// BitsDiferentes conta quantos bits diferem entre dois buffers.
func BitsDiferentes(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	diff := 0
	for i := 0; i < n; i++ {
		diff += ContarBits1(a[i] ^ b[i])
	}
	return diff
}

// Shuffle embaralha uma cópia do slice (Fisher-Yates).
func Shuffle[T any](array []T) []T {
	out := make([]T, len(array))
	copy(out, array)
	for i := len(out) - 1; i > 0; i-- {
		j := RandomInt(0, i)
		out[i], out[j] = out[j], out[i]
	}
	return out
}
