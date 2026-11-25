package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

const (
	filterTable               = "filter"
	outputChain               = "OUTPUT"
	dockerUserChain           = "DOCKER-USER"
	dockerInterface           = "docker0"
	fallbackInterface         = "eth0"
	procNetRoutePath          = "/proc/net/route"
	inbound                   = "-i"
	outbound                  = "-o"
	protocol                  = "-p"
	allProtocols              = "all"
	tcp                       = "tcp"
	udp                       = "udp"
	destination               = "-d"
	destinationPort           = "--dport"
	target                    = "-j"
	accept                    = "ACCEPT"
	reject                    = "REJECT"
	nflogTarget               = "NFLOG"
	nflogGroup                = "100"
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

// interface carrying the default route; not always eth0 (e.g. enp39s0 on AWS-hosted runners)
var defaultInterface = fallbackInterface

type ipAddressEndpoint struct {
	ipAddress string
	port      string
}

// initDefaultInterface sets defaultInterface from the default route, falling back to eth0
func initDefaultInterface() {
	iface, err := detectDefaultInterface(procNetRoutePath)
	if err != nil {
		WriteLog(fmt.Sprintf("unable to detect default interface, using %s: %v", fallbackInterface, err))
		WriteAnnotation(fmt.Sprintf("%s Unable to detect default network interface, using %s: %v", StepSecurityAnnotationPrefix, fallbackInterface, err))
		defaultInterface = fallbackInterface
		return
	}

	defaultInterface = iface
	WriteLog(fmt.Sprintf("default interface: %s", defaultInterface))
}

func detectDefaultInterface(routeFile string) (string, error) {
	f, err := os.Open(routeFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	return parseDefaultInterface(f)
}

// parseDefaultInterface returns the lowest-metric default route interface from /proc/net/route content
func parseDefaultInterface(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // header

	iface := ""
	bestMetric := -1
	for scanner.Scan() {
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}

		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}

		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}

		if bestMetric == -1 || metric < bestMetric {
			iface, bestMetric = fields[0], metric
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	if iface == "" {
		return "", errors.New("no default route found")
	}

	return iface, nil
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
	dnsServers := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}

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
			return fmt.Errorf("ClearChain failed for DOCKER-USER: %v", err)
		}
	}

	// Agent uses HTTPs to resolve domain names
	// Only apply UID filtering for OUTPUT chain
	if chain == outputChain {
		agentUID := fmt.Sprintf("%d", os.Getuid())
		for _, dnsServer := range dnsServers {
			err = ipt.Append(filterTable, chain, direction, netInterface,
				"-m", "owner", "--uid-owner", agentUID,
				protocol, tcp,
				destination, dnsServer,
				destinationPort, "443",
				target, accept)

			if err != nil {
				return errors.Wrapf(err, "failed to add rule for DNS server %s", dnsServer)
			}
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

	// Log blocked traffic - UDP packets
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, "udp", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return errors.Wrap(err, "failed to add UDP NFLOG rule")
	}

	// Block all other traffic
	err = ipt.Append(filterTable, chain, direction, netInterface, protocol, allProtocols, target, reject)

	if err != nil {
		return fmt.Errorf("Append failed: %v", err)
	}

	return nil
}

func InsertAllowRule(firewall *Firewall, blocklist *GlobalBlocklist, ipAddress, port string) error {
	if blocklist != nil && blocklist.IsIPAddressBlocked(ipAddress) {
		return nil
	}

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

func AddGlobalBlockRules(firewall *Firewall, blocklist *GlobalBlocklist) error {
	if blocklist == nil {
		return nil
	}

	if err := addGlobalBlockRulesForChain(firewall, blocklist, outputChain, defaultInterface, outbound); err != nil {
		return errors.Wrap(err, "failed to add global block rules for default interface")
	}

	if err := addGlobalBlockRulesForChain(firewall, blocklist, dockerUserChain, dockerInterface, inbound); err != nil {
		return errors.Wrap(err, "failed to add global block rules for docker interface")
	}

	return nil
}

func addGlobalBlockRulesForChain(firewall *Firewall, blocklist *GlobalBlocklist, chain, netInterface, direction string) error {
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

	// Add NFLOG rules once for all blocked IPs (TCP SYN + UDP)
	tcpNflogExists, err := ipt.Exists(filterTable, chain, direction, netInterface, protocol, tcp, "--tcp-flags", "SYN,ACK", "SYN", target, nflogTarget, "--nflog-group", nflogGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to check global block tcp nflog rule interface:%s", netInterface)
	}
	if !tcpNflogExists {
		err = ipt.Insert(filterTable, chain, 1, direction, netInterface, protocol, tcp, "--tcp-flags", "SYN,ACK", "SYN", target, nflogTarget, "--nflog-group", nflogGroup)
		if err != nil {
			return errors.Wrapf(err, "failed to insert global block tcp nflog rule interface:%s", netInterface)
		}
	}

	udpNflogExists, err := ipt.Exists(filterTable, chain, direction, netInterface, protocol, udp, target, nflogTarget, "--nflog-group", nflogGroup)
	if err != nil {
		return errors.Wrapf(err, "failed to check global block udp nflog rule interface:%s", netInterface)
	}
	if !udpNflogExists {
		err = ipt.Insert(filterTable, chain, 2, direction, netInterface, protocol, udp, target, nflogTarget, "--nflog-group", nflogGroup)
		if err != nil {
			return errors.Wrapf(err, "failed to insert global block udp nflog rule interface:%s", netInterface)
		}
	}

	for _, ipAddress := range blocklist.GetBlockedIPAddresses() {
		if err := addGlobalBlockRule(ipt, chain, direction, netInterface, ipAddress); err != nil {
			return err
		}
	}

	return nil
}

func addGlobalBlockRule(ipt IPTables, chain, direction, netInterface, ipAddress string) error {
	exists, err := ipt.Exists(filterTable, chain, direction, netInterface, destination, ipAddress, target, reject)
	if err != nil {
		return errors.Wrapf(err, "failed to check global block rule ip:%s, interface:%s", ipAddress, netInterface)
	}
	if exists {
		return nil
	}

	err = ipt.Insert(filterTable, chain, 3, direction, netInterface, destination, ipAddress, target, reject)
	if err != nil {
		return errors.Wrapf(err, "failed to insert global block rule ip:%s, interface:%s", ipAddress, netInterface)
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
	err = ipt.Append("filter", "OUTPUT", "-o", defaultInterface, "-p", "udp", "--dport", "53", "-j", "DROP")
	//err = ipt.Append("filter", "OUTPUT", "-o", defaultInterface, "-p", "udp", "-j", "DROP")
	if err != nil {
		return errors.Wrap(err, "failed to deny udp")
	}

	// this limits the number of packets sent to nflog. Only SYN requests are sent
	err = ipt.Append("filter", "OUTPUT", "-o", defaultInterface, "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return fmt.Errorf("Append failed for %s: %v", defaultInterface, err)
	}

	err = ipt.ClearChain("filter", "DOCKER-USER")

	if err != nil {
		return fmt.Errorf("ClearChain failed for DOCKER-USER: %v", err)
	}

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "udp", "--dport", "53", "-j", "DROP")

	if err != nil {
		return fmt.Errorf("failed to deny udp docker interface: %v", err)
	}

	err = ipt.Append("filter", "DOCKER-USER", "-i", "docker0", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN", "-j", "NFLOG", "--nflog-group", "100")

	if err != nil {
		return fmt.Errorf("Append failed for FORWARD: %v", err)
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
