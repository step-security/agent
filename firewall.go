package main

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

const (
	filterTable      = "filter"
	outputChain      = "OUTPUT"
	dockerUserChain  = "DOCKER_USER"
	dockerInterface  = "docker0"
	defaultInterface = "eth0"
	inbound          = "-i"
	outbound         = "-o"
	protocol         = "-p"
	allProtocols     = "all"
	tcp              = "tcp"
	destination      = "-d"
	destinationPort  = "--dport"
	target           = "-j"
	accept           = "ACCEPT"
	reject           = "REJECT"
	dnsServerIP      = "8.8.8.8"
)

type ipAddressEndpoint struct {
	ipAddress string
	port      string
}

func addBlockRulesForGitHubHostedRunner(endpoints []ipAddressEndpoint) error {
	err := addBlockRules(endpoints, outputChain, defaultInterface, outbound)
	if err != nil {
		return errors.Wrap(err, "failed to add block rules for default interface")
	}

	err = addBlockRules(endpoints, dockerUserChain, dockerInterface, inbound)
	if err != nil {
		return errors.Wrap(err, "failed to add block rules for docker interface")
	}

	return nil
}

func addBlockRules(endpoints []ipAddressEndpoint, chain, netInterface, direction string) error {
	ipt, err := iptables.New()
	if err != nil {
		return errors.Wrap(err, "new iptables failed")
	}

	if chain == dockerUserChain {
		err = ipt.ClearChain(filterTable, dockerUserChain)

		if err != nil {
			return fmt.Errorf(fmt.Sprintf("ClearChain failed for DOCKER-USER: %v", err))
		}
	}

	for _, endpoint := range endpoints {
		err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp,
			destination, endpoint.ipAddress,
			destinationPort, endpoint.port, target, accept)

		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to append endpoint rule ip:%s, port:%s", endpoint.ipAddress, endpoint.port))
		}
	}

	// Agent uses HTTPs to resolve domain names
	// Allow 8.8.8.8 for dns
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp,
		destination, dnsServerIP, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Allow established connections
	// By the time agent starts, some connections are already established that should not be blocked
	err = ipt.Append(filterTable, chain, direction, netInterface,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Log blocked traffic
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp, "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Block all other traffic
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, allProtocols, target, reject)

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Append failed: %v", err))
	}

	return nil
}

func addAuditRules(firewall *Firewall) error {
	var ipt IPTables
	var err error
	if firewall == nil {

		ipt, err = iptables.New()

		if err != nil {
			return errors.Wrap(err, "new iptables failed")
		}
	} else {
		ipt = firewall.IPTables
	}

	// deny DNS on port 53
	// TODO: Deny UDP overall?
	//err = ipt.Append("filter", "OUTPUT", "-o", "eth0", "-p", "udp", "--dport", "53", "-j", "DROP")
	err = ipt.Append("filter", "OUTPUT", "-o", "eth0", "-p", "udp", "-j", "DROP")
	if err != nil {
		return errors.Wrap(err, "failed to deny udp")
	}

	// this limits the number of packets sent to nflog. Only SYN requests are sent
	err = ipt.Append("filter", "OUTPUT", "-o", "eth0", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Append failed for eth0: %v", err))
	}

	err = ipt.ClearChain("filter", "DOCKER-USER")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("ClearChain failed for DOCKER-USER: %v", err))
	}

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "udp", "-j", "DROP")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to deny udp docker interface: %v", err))
	}

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Append failed for FORWARD: %v", err))
	}

	return nil
}
