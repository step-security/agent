package main

import (
	"strings"

	"github.com/miekg/dns"
)

const GlobalBlocklistMatchedPolicy = "GLOBAL_BLOCKLIST"

type CompromisedEndpoint struct {
	Endpoint string `json:"endpoint"`
	Reason   string `json:"reason,omitempty"`
}

type GlobalBlocklistResponse struct {
	IPAddresses     []CompromisedEndpoint `json:"ip_addresses,omitempty"`
	Domains         []CompromisedEndpoint `json:"domains,omitempty"`
	WildcardDomains []CompromisedEndpoint `json:"wildcard_domains,omitempty"`
}

type GlobalBlocklist struct {
	ipAddresses     map[string]string
	domains         map[string]string
	wildcardDomains map[string]string
}

func NewGlobalBlocklist(response *GlobalBlocklistResponse) *GlobalBlocklist {
	blocklist := &GlobalBlocklist{
		ipAddresses:     make(map[string]string),
		domains:         make(map[string]string),
		wildcardDomains: make(map[string]string),
	}

	if response == nil {
		return blocklist
	}

	for _, endpoint := range response.IPAddresses {
		ipAddress := strings.TrimSpace(strings.ToLower(endpoint.Endpoint))
		if ipAddress != "" {
			blocklist.ipAddresses[ipAddress] = endpoint.Reason
		}
	}

	for _, endpoint := range response.Domains {
		domain := normalizeBlocklistDomain(endpoint.Endpoint)
		if domain != "" {
			blocklist.domains[domain] = endpoint.Reason
		}
	}

	for _, endpoint := range response.WildcardDomains {
		domain := normalizeWildcardBlocklistDomain(endpoint.Endpoint)
		if domain != "" {
			blocklist.wildcardDomains[domain] = endpoint.Reason
		}
	}

	return blocklist
}

func (blocklist *GlobalBlocklist) IsIPAddressBlocked(ipAddress string) bool {
	if blocklist == nil {
		return false
	}

	_, found := blocklist.ipAddresses[strings.TrimSpace(strings.ToLower(ipAddress))]
	return found
}

func (blocklist *GlobalBlocklist) BlockedIPAddressReason(ipAddress string) string {
	if blocklist == nil {
		return ""
	}

	return blocklist.ipAddresses[strings.TrimSpace(strings.ToLower(ipAddress))]
}

func (blocklist *GlobalBlocklist) GetBlockedIPAddresses() []string {
	if blocklist == nil {
		return nil
	}

	ipAddresses := make([]string, 0, len(blocklist.ipAddresses))
	for ipAddress := range blocklist.ipAddresses {
		ipAddresses = append(ipAddresses, ipAddress)
	}

	return ipAddresses
}

func (blocklist *GlobalBlocklist) IsDomainBlocked(domain string) (bool, string) {
	if blocklist == nil {
		return false, ""
	}

	normalizedDomain := normalizeBlocklistDomain(domain)
	if normalizedDomain == "" {
		return false, ""
	}

	if reason, found := blocklist.domains[normalizedDomain]; found {
		return true, reason
	}

	return blocklist.matchesBlockedWildcardDomain(normalizedDomain)
}

func (blocklist *GlobalBlocklist) BlockedDomainReason(domain string) string {
	_, reason := blocklist.IsDomainBlocked(domain)
	return reason
}

func (blocklist *GlobalBlocklist) IsWildcardDomainBlocked(domain string) (bool, string) {
	if blocklist == nil {
		return false, ""
	}

	normalizedDomain := normalizeWildcardBlocklistDomain(domain)
	if normalizedDomain == "" {
		return false, ""
	}

	for wildcardDomain, reason := range blocklist.wildcardDomains {
		if normalizedDomain == wildcardDomain || strings.HasSuffix(normalizedDomain, "."+wildcardDomain) {
			return true, reason
		}
	}

	return false, ""
}

func (blocklist *GlobalBlocklist) matchesBlockedWildcardDomain(normalizedDomain string) (bool, string) {
	for wildcardDomain, reason := range blocklist.wildcardDomains {
		if strings.HasSuffix(normalizedDomain, "."+wildcardDomain) {
			return true, reason
		}
	}

	return false, ""
}

func normalizeBlocklistDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}

	return dns.Fqdn(domain)
}

func normalizeWildcardBlocklistDomain(domain string) string {
	domain = normalizeBlocklistDomain(domain)
	return strings.TrimPrefix(domain, "*.")
}
