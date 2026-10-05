package utils

import (
	"context"
	"sync"
	"time"
)

// RateLimiter é um limitador global de requisições por segundo baseado em
// canal-tique. Um goroutine "metrônomo" envia um token ao canal a cada
// 1/rps segundos; consumidores bloqueiam em Wait() antes de cada request.
// Isso serializa o ritmo entre TODOS os módulos que compartilham o mesmo
// limiter, independente do número de threads internos de cada ferramenta.
type RateLimiter struct {
	interval time.Duration
	tokens   chan struct{}
	once     sync.Once
	stop     chan struct{}
}

// NewRateLimiter cria e inicia um limiter para rps requisições/segundo.
// Se rps <= 0, Wait() vira no-op (sem limite).
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return &RateLimiter{}
	}
	rl := &RateLimiter{
		interval: time.Second / time.Duration(rps),
		tokens:   make(chan struct{}, rps), // pequeno buffer para absorver jitter
		stop:     make(chan struct{}),
	}
	go rl.tick()
	return rl
}

func (rl *RateLimiter) tick() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
				// Canal cheio = consumidores atrasados; descartamos o
				// tique em vez de acumular "créditos" de burst.
			}
		case <-rl.stop:
			return
		}
	}
}

// Wait bloqueia até obter permissão para enviar mais uma requisição.
func (rl *RateLimiter) Wait() {
	if rl == nil || rl.tokens == nil {
		return
	}
	<-rl.tokens
}

// WaitCtx é como Wait, mas abortável (contexto cancelado devolve erro).
func (rl *RateLimiter) WaitCtx(ctx context.Context) error {
	if rl == nil || rl.tokens == nil {
		return nil
	}
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop encerra o goroutine metrônomo. Seguro chamar múltiplas vezes.
func (rl *RateLimiter) Stop() {
	if rl == nil || rl.tokens == nil {
		return
	}
	rl.once.Do(func() { close(rl.stop) })
}
