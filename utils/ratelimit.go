package utils

import (
"context"
"sync"
"time"
)

type RateLimiter struct {
interval time.Duration
tokens   chan struct{}
once     sync.Once
stop     chan struct{}
}

func NewRateLimiter(rps int) *RateLimiter {
if rps <= 0 {
return &RateLimiter{}
}
rl := &RateLimiter{
interval: time.Second / time.Duration(rps),
tokens:   make(chan struct{}, rps),
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
}
case <-rl.stop:
return
}
}
}

func (rl *RateLimiter) Wait() {
if rl == nil || rl.tokens == nil {
return
}
<-rl.tokens
}

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

func (rl *RateLimiter) Stop() {
if rl == nil || rl.tokens == nil {
return
}
rl.once.Do(func() { close(rl.stop) })
}
