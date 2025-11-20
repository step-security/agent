package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
)

const Unknown = "Unknown"

type NetworkMonitor struct {
	CorrelationId string
	Repo          string
	ApiClient     *ApiClient
	Status        string
	netMutex      sync.RWMutex
}

var ipAddresses = make(map[string]int)

func (netMonitor *NetworkMonitor) MonitorNetwork(ctx context.Context, nflogger AgentNflogger, errc chan error) []string {

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
	isUDP := false
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		port = tcp.DstPort.String()
		isSYN = tcp.SYN

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// Get actual UDP data from this layer
		udp, _ := udpLayer.(*layers.UDP)
		port = udp.DstPort.String()
		isUDP = true
	}

	// Get the IP layer from this packet
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		// Get actual TCP data from this layer
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		netMonitor.netMutex.Lock()
		ipv4Address := ipv4.DstIP.String()
		_, found := ipAddresses[ipv4Address]
		if !found {
			ipAddresses[ipv4Address] = 1

			if isSYN || isUDP {
				if netMonitor.Status == "Dropped" {

					netMonitor.ApiClient.sendNetConnection(netMonitor.CorrelationId, netMonitor.Repo,
						ipv4Address, port, "", netMonitor.Status, timestamp, Tool{Name: Unknown, SHA256: Unknown})

					go WriteLog(fmt.Sprintf("ip address dropped: %s", ipv4Address))

					if ipv4Address != StepSecuritySinkHoleIPAddress { // Sinkhole IP address will be covered by DNS block
						go WriteAnnotation(fmt.Sprintf("StepSecurity Harden Runner: Traffic to IP Address %s was blocked", ipv4Address))
					}
				}
			}
		}
		netMonitor.netMutex.Unlock()
	}

}
