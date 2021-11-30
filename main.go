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
	signal.Notify(signalChan, os.Kill, syscall.SIGHUP)

	c := &config{}

	defer func() {
		signal.Stop(signalChan)
		cancel()
	}()

	go func() {
		for {
			select {
			case s := <-signalChan:
				switch s {
				case syscall.SIGHUP:
					c.init(agentConfigFilePath)
				case os.Interrupt:
					writeLog("got os.kill")
					cancel()
					os.Exit(1)
				}
			case <-ctx.Done():
				writeLog("called ctx.Done()")
				os.Exit(1)
			}
		}
	}()

	if err := Run(ctx, agentConfigFilePath, &dns.Server{Addr: "127.0.0.1:53", Net: "udp"},
		&dns.Server{Addr: "172.17.0.1:53", Net: "udp"}, nil, nil, nil, resolvedConfigPath, dockerDaemonConfigPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
