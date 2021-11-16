package main

import (
	"context"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
)

type NetworkMonitor struct {
	CorrelationId string
	Repo          string
	ApiClient     *ApiClient
	Status        string
}

var ipAddresses = make(map[string]int)

func (netMonitor *NetworkMonitor) MonitorNetwork(nflogger AgentNflogger, errc chan error) []string {

	//sysLogger, err := syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_USER, 1)
	var err error
	config := nflog.Config{
		Group:    100,
		Copymode: nflog.CopyPacket,
		//	Logger:   sysLogger,
		//ReadTimeout: 100 * time.Millisecond,
	}
	var nf NfLogger
	if nflogger == nil {
		nf, err = nflog.Open(&config)
		if err != nil {
			errc <- errors.Wrap(err, "failed to open nflog")
		}
	} else {
		nf, err = nflogger.Open(&config) // for mock
		if err != nil {
			errc <- errors.Wrap(err, "failed to open nflog")
		}
	}
	defer nf.Close()

	ctx, cancel := context.WithCancel(context.Background()) // TODO: Pass context from the top
	defer cancel()

	fn := func(attrs nflog.Attribute) int {
		go netMonitor.handlePacket(attrs)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.Register(ctx, fn)
	if err != nil {
		errc <- errors.Wrap(err, "failed to register nflog")
	}

	// Block till the context expires
	<-ctx.Done()

	return nil
}

func (netMonitor *NetworkMonitor) handlePacket(attrs nflog.Attribute) {
	timestamp := time.Now().UTC() // *attrs.Timestamp
	data := *attrs.Payload
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	port := ""
	isSYN := false
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		port = tcp.DstPort.String()
		isSYN = tcp.SYN

	}

	// Get the IP layer from this packet
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		// Get actual TCP data from this layer
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		_, found := ipAddresses[ipv4.DstIP.String()]
		if !found {
			ipAddresses[ipv4.DstIP.String()] = 1

			if isSYN {
				netMonitor.ApiClient.sendNetConnection(netMonitor.CorrelationId, netMonitor.Repo,
					ipv4.DstIP.String(), port, netMonitor.Status, timestamp, "Unknown", "Unknown")
			}
		}

	}

}
