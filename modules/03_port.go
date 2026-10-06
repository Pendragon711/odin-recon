package modules

import (
"context"
"fmt"

"odin/utils"

"github.com/projectdiscovery/naabu/v2/pkg/result"
"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type PortResult struct {
Subdomain string
IP        string
Port      int
}

type PortScanOptions struct {
Ports     string
Rate      int
TimeoutMs int
}

func RunPortScan(hosts []string, hostToIP map[string]string, opts PortScanOptions) ([]PortResult, error) {
utils.LogInfo(fmt.Sprintf("Iniciando varredura de portas web para %d hosts...", len(hosts)))
if len(hosts) == 0 {
utils.LogWarning("Nenhum host com DNS resolvido para escanear portas.")
return nil, nil
}

portsFlag := opts.Ports
if portsFlag == "" {
portsFlag = "80,443,8000,8080,8443,8888,9000,9090,9443"
}

var results []PortResult
reverseHost := make(map[string]string, len(hosts))
for _, h := range hosts {
if ip, ok := hostToIP[h]; ok && ip != "" {
reverseHost[ip] = h
}
}

ipList := make([]string, 0, len(hosts))
for _, h := range hosts {
if ip, ok := hostToIP[h]; ok && ip != "" {
ipList = append(ipList, ip)
}
}

runnerOpts := &runner.Options{
Host:   ipList,
Silent: true,
OnResult: func(hr *result.HostResult) {
hostname := hr.Host
if h, ok := reverseHost[hr.Host]; ok {
hostname = h
}
ip := hostToIP[hostname]
if ip == "" {
ip = hr.Host
}
for _, port := range hr.Ports {
results = append(results, PortResult{
Subdomain: hostname,
IP:        ip,
Port:      port.Port,
})
}
},
}

if portsFlag == "top-1000" {
runnerOpts.TopPorts = "1000"
} else {
runnerOpts.Ports = portsFlag
}
if opts.Rate > 0 {
runnerOpts.Rate = opts.Rate
}

naabuRunner, err := runner.NewRunner(runnerOpts)
if err != nil {
return nil, fmt.Errorf("erro ao inicializar o Naabu: %w", err)
}
err = naabuRunner.RunEnumeration(context.Background())
if err != nil {
return nil, fmt.Errorf("erro durante a varredura de portas: %w", err)
}

utils.LogSuccess(fmt.Sprintf("Mapeamento concluído: %d combinações de host:porta abertas.", len(results)))
return results, nil
}
