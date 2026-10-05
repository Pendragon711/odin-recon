package modules

import (
	"fmt"
	"testing"
)

func mk(sub, hash string, sh uint64) HTTPResult {
	return HTTPResult{Subdomain: sub, BodyHash: hash, SimHash: sh}
}

func mkWithSource(sub, hash string, sh uint64, source string) HTTPResult {
	r := mk(sub, hash, sh)
	r.HashSource = source
	return r
}

func TestMarkBlockPagesExact(t *testing.T) {
	var rs []HTTPResult
	for i := 0; i < 5; i++ {
		rs = append(rs, mkWithSource(string(rune('a'+i)), "samehash", 0, "body"))
	}
	rs = append(rs, mkWithSource("real1", "unique1", 0, "body"))
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
		sh := base ^ (uint64(1) << uint(i)) // difere em 1 bit do vizinho -> similar
		rs = append(rs, HTTPResult{Subdomain: n, BodyHash: "different" + n, SimHash: sh, HashSource: "body"})
	}
	// Host legítimo: simhash muito distante de todos.
	rs = append(rs, HTTPResult{Subdomain: "legit", BodyHash: "other", SimHash: 0x00000000000000FF, HashSource: "body"})
	// A camada de similaridade só roda acima do volume mínimo de respostas;
	// preenche com hosts únicos distantes p/ passar no gate sem afetar o teste.
	fillerBase := uint64(0x1111111111111111)
	j := 0
	for len(rs) < similarityLayerMinResults {
		filler := fillerBase ^ (uint64(0xF0F0F0F0F0F0F0F0) << uint(j%4) * 16)
		rs = append(rs, HTTPResult{Subdomain: fmt.Sprintf("filler%d", j), BodyHash: fmt.Sprintf("fillerhash%d", j), SimHash: filler, HashSource: "body"})
		j++
	}
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
