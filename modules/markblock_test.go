package modules

import "testing"

func mk(sub, hash string, sh uint64) HTTPResult {
return HTTPResult{Subdomain: sub, BodyHash: hash, SimHash: sh}
}

func TestMarkBlockPagesExact(t *testing.T) {
var rs []HTTPResult
for i := 0; i < 5; i++ {
rs = append(rs, mk(string(rune('a'+i)), "samehash", 0))
}
rs = append(rs, mk("real1", "unique1", 0))
markBlockPages(rs)
for _, r := range rs[:5] {
if !r.BlockPage || r.BlockReason != "exact" {
t.Fatalf("expected exact blockpage for %s", r.Subdomain)
}
}
if rs[5].BlockPage {
t.Fatal("unique host should not be marked")
}
}

func TestMarkBlockPagesSimilar(t *testing.T) {
base := uint64(0xAAAAAAAAAAAAAAAA)
var rs []HTTPResult
// Mesmo body_hash não funciona aqui: cada host tem hash exato diferente.
names := []string{"h1", "h2", "h3", "h4", "h5"}
for i, n := range names {
sh := base ^ (1 << uint(i)) // difere em 1 bit do vizinho -> similar
rs = append(rs, HTTPResult{Subdomain: n, BodyHash: "different" + n, SimHash: sh})
}
// Host legítimo: simhash muito distante de todos.
rs = append(rs, HTTPResult{Subdomain: "legit", BodyHash: "other", SimHash: 0x00000000000000FF})
markBlockPages(rs)
for i := 0; i < 5; i++ {
if !rs[i].BlockPage || rs[i].BlockReason != "similar" {
t.Fatalf("expected similar blockpage for %s, got %+v", rs[i].Subdomain, rs[i])
}
}
if rs[5].BlockPage {
t.Fatal("legit host with distant simhash must not be marked")
}
}
