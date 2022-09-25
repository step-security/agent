package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

const agentConfigFilePath = "agent.json"

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	go func() {
		for {
			select {
			case <-signalChan:
				WriteAnnotation(fmt.Sprintf("%s Received SIGTERM signal", StepSecurityAnnotationPrefix))
			case <-ctx.Done():
				WriteLog("called ctx.Done()")
				os.Exit(1)
			}
		}
	}()

	if err := Run(ctx, agentConfigFilePath, &dns.Server{Addr: "127.0.0.1:53", Net: "udp"},
		&dns.Server{Addr: "172.17.0.1:53", Net: "udp"}, nil, nil, nil, resolvedConfigPath, dockerDaemonConfigPath, os.TempDir()); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
