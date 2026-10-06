package utils

import (
"crypto/md5"
)

// Simhash calcula um hash de 64 bits baseado na similaridade do conteúdo.
// É útil para detectar páginas quase idênticas (ex: WAFs com nonces dinâmicos).
func Simhash(content []byte) uint64 {
if len(content) == 0 {
return 0
}

var v [64]int

// Dividimos o conteúdo em chunks de 4 bytes para gerar features
for i := 0; i < len(content); i += 4 {
end := i + 4
if end > len(content) {
end = len(content)
}
chunk := content[i:end]

hash := md5.Sum(chunk)
for j := 0; j < 64; j++ {
bitIndex := j % 32 // Usamos os 32 bits do hash MD5 repetidamente
if (hash[bitIndex/8] & (1 << (bitIndex % 8))) != 0 {
v[j] += 1
} else {
v[j] -= 1
}
}
}

var fingerprint uint64
for i := 0; i < 64; i++ {
if v[i] > 0 {
fingerprint |= (1 << uint(i))
}
}
return fingerprint
}
