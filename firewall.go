package main

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

const (
	filterTable               = "filter"
	outputChain               = "OUTPUT"
	dockerUserChain           = "DOCKER-USER"
	dockerInterface           = "docker0"
	defaultInterface          = "eth0"
	inbound                   = "-i"
	outbound                  = "-o"
	protocol                  = "-p"
	allProtocols              = "all"
	tcp                       = "tcp"
	destination               = "-d"
	destinationPort           = "--dport"
	target                    = "-j"
	accept                    = "ACCEPT"
	reject                    = "REJECT"
	dnsServerIP               = "8.8.8.8"
	dnsServerIP2              = "8.8.4.4"
	classAPrivateAddressRange = "10.0.0.0/8"
	classBPrivateAddressRange = "172.16.0.0/12"
	classCPrivateAddressRange = "192.168.0.0/16"
	ipv6LinkLocalAddressRange = "fe80::/10"
	ipv6LocalAddressRange     = "fc00::/7"
	loopBackAddressRange      = "127.0.0.0/8"
	AzureIPAddress            = "168.63.129.16"
	MetadataIPAddress         = "169.254.169.254"
	AllZeros                  = "0.0.0.0"
)

type ipAddressEndpoint struct {
	ipAddress string
	port      string
}

func addBlockRulesForGitHubHostedRunner(firewall *Firewall, endpoints []ipAddressEndpoint) error {
	err := addBlockRules(firewall, endpoints, outputChain, defaultInterface, outbound)
	if err != nil {
		return errors.Wrap(err, "failed to add block rules for default interface")
	}

	err = addBlockRules(firewall, endpoints, dockerUserChain, dockerInterface, inbound)
	if err != nil {
		return errors.Wrap(err, "failed to add block rules for docker interface")
	}

	return nil
}

func addBlockRules(firewall *Firewall, endpoints []ipAddressEndpoint, chain, netInterface, direction string) error {
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

	// Allow 8.8.4.4 for dns
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp,
		destination, dnsServerIP2, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Allow AzureIPAddress
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp,
		destination, AzureIPAddress, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Allow Metadata service
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, tcp,
		destination, MetadataIPAddress, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	// Allow private IP ranges
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, allProtocols,
		destination, classAPrivateAddressRange, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, allProtocols,
		destination, classBPrivateAddressRange, target, accept)

	if err != nil {
		return errors.Wrap(err, "failed to add rule")
	}

	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, allProtocols,
		destination, classCPrivateAddressRange, target, accept)

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

func InsertAllowRule(firewall *Firewall, ipAddress, port string) error {
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

	exists, err := ipt.Exists(filterTable, outputChain, outbound, defaultInterface, protocol, tcp,
		destination, ipAddress,
		destinationPort, port, target, accept)

	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to check if endpoint exists ip:%s, port:%s, interface:%s", ipAddress, port, defaultInterface))
	}

	if !exists {
		err = ipt.Insert(filterTable, outputChain, 1, outbound, defaultInterface, protocol, tcp,
			destination, ipAddress,
			destinationPort, port, target, accept)

		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to insert endpoint rule ip:%s, port:%s, interface:%s", ipAddress, port, defaultInterface))
		}
	}

	exists, err = ipt.Exists(filterTable, dockerUserChain, inbound, dockerInterface, protocol, tcp,
		destination, ipAddress,
		destinationPort, port, target, accept)

	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to check if endpoint exists ip:%s, port:%s, interface:%s", ipAddress, port, dockerInterface))
	}

	if !exists {
		err = ipt.Insert(filterTable, dockerUserChain, 1, inbound, dockerInterface, protocol, tcp,
			destination, ipAddress,
			destinationPort, port, target, accept)

		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to insert endpoint rule ip:%s, port:%s, interface:%s", ipAddress, port, defaultInterface))
		}
	}

	return nil
}

func AddAuditRules(firewall *Firewall) error {
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

	// deny DNS on port 53, else it interferes with DNS proxy
	// Do not Deny UDP overall as developers may be using it, e.g. MS QUIC
	// https://github.com/step-security/harden-runner/issues/112
	err = ipt.Append("filter", "OUTPUT", "-o", "eth0", "-p", "udp", "--dport", "53", "-j", "DROP")
	//err = ipt.Append("filter", "OUTPUT", "-o", "eth0", "-p", "udp", "-j", "DROP")
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

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "udp", "--dport", "53", "-j", "DROP")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("failed to deny udp docker interface: %v", err))
	}

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return fmt.Errorf(fmt.Sprintf("Append failed for FORWARD: %v", err))
	}

	return nil
}

func RevertFirewallChanges(firewall *Firewall) error {
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

	ipt.ClearChain("filter", "OUTPUT")
	ipt.ClearChain("filter", "DOCKER-USER")

	return nil
}
