package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

type DNSProxy struct {
	Cache                *Cache
	CorrelationId        string
	Repo                 string
	ApiClient            *ApiClient
	EgressPolicy         string
	AllowedEndpoints     map[string][]Endpoint
	WildCardEndpoints    map[string][]Endpoint
	ReverseIPLookup      map[string]string
	ReverseIPLookupMutex sync.RWMutex
	Iptables             *Firewall
}

type DNSResponse struct {
	Status   int        `json:"Status"`
	Tc       bool       `json:"TC"`
	Rd       bool       `json:"RD"`
	Ra       bool       `json:"RA"`
	Ad       bool       `json:"AD"`
	Cd       bool       `json:"CD"`
	Question []Question `json:"Question"`
	Answer   []Answer   `json:"Answer"`
}
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

const StepSecuritySinkHoleIPAddress = "54.185.253.63"

func (proxy *DNSProxy) getResponse(requestMsg *dns.Msg) (*dns.Msg, error) {

	responseMsg := new(dns.Msg)

	if len(requestMsg.Question) > 0 {
		question := requestMsg.Question[0]

		switch question.Qtype {
		case dns.TypeA:

			answer, err := proxy.processTypeA(&question, requestMsg)
			if err != nil {
				return responseMsg, err
			}
			responseMsg.Answer = append(responseMsg.Answer, *answer)

		default:
			answer, err := proxy.processOtherTypes(&question, requestMsg)
			if err != nil {
				return responseMsg, err
			}
			responseMsg.Answer = append(responseMsg.Answer, *answer)
		}
	}

	return responseMsg, nil
}

func (proxy *DNSProxy) SetReverseIPLookup(domain, ipAddress string) {
	proxy.ReverseIPLookupMutex.Lock()

	proxy.ReverseIPLookup[ipAddress] = domain

	proxy.ReverseIPLookupMutex.Unlock()
}

func (proxy *DNSProxy) GetReverseIPLookup(ipAddress string) string {
	proxy.ReverseIPLookupMutex.RLock()
	domain, found := proxy.ReverseIPLookup[ipAddress]
	proxy.ReverseIPLookupMutex.RUnlock()
	if found {
		return domain
	} else {
		return ""
	}
}

func (proxy *DNSProxy) processOtherTypes(q *dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	return nil, fmt.Errorf("not found")
}

func (proxy *DNSProxy) isAllowedDomain(domain string) bool {
	for domainName := range proxy.AllowedEndpoints {
		if dns.Fqdn(domainName) == dns.Fqdn(domain) {
			return true
		}
	}

	return false
}

func (proxy *DNSProxy) ResolveDomain(domain string) (*Answer, error) {
	url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=a", domain)
	fallbackUrl := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A", domain)
	retryCounter := 0
	var httpError error
	var resp *http.Response
	for retryCounter < 2 {
		requestUrl := url
		if retryCounter == 1 {
			requestUrl = fallbackUrl
		}
		req, _ := http.NewRequest("GET", requestUrl, nil)
		req.Header.Add("accept", "application/dns-json")
		resp, httpError = proxy.ApiClient.Client.Do(req)
		if httpError != nil {
			retryCounter++
		} else {
			break
		}
	}

	if httpError != nil {
		return nil, fmt.Errorf("error in response from dns.google %v", httpError)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("error in response from dns.google %v", err)
	}

	var dnsResponse DNSResponse

	err = json.Unmarshal([]byte(body), &dnsResponse)

	if err != nil {
		return nil, fmt.Errorf("error in response from dns.google %v", err)
	}

	for _, answer := range dnsResponse.Answer {
		if answer.Type == 1 {
			if answer.TTL < 30 {
				answer.TTL = 30 // less than 30 will cause too frequent DNS requests in audit scenario
			}
			return &answer, nil
		}
	}

	return nil, fmt.Errorf("unable to resolve domain %s, status %d", domain, dnsResponse.Status)
}

func getDomainFromCloudAppFormat(domain string) string {
	domainParts := strings.Split(domain, ".")
	totalDots := len(domainParts) - 6
	finalDomain := ""
	for i := 0; i < totalDots; i++ {
		finalDomain += domainParts[i] + "."
	}

	return finalDomain
}

func (proxy *DNSProxy) getIPByDomain(domain string) (string, error) {
	domain = dns.Fqdn(domain)

	cacheMsg, found := proxy.Cache.Get(domain)

	if found {
		return cacheMsg.Value.Data, nil
	}

	matchesAnyWildcard := false
	wildcardPort := ""

	if proxy.EgressPolicy == EgressPolicyBlock {
		if strings.HasSuffix(domain, ".internal.") {
			go WriteLog(fmt.Sprintf("unable to resolve internal domains: %s", domain))
			return "", fmt.Errorf("cannot resolve internal domains")
		}

		if !proxy.isAllowedDomain(domain) {
			matchesAnyWildcard, wildcardPort = proxy.matchAnyWildcard(domain)
			if !matchesAnyWildcard {
				go WriteLog(fmt.Sprintf("domain not allowed: %s", domain))

				// call to api.snapcraft.io is made by snapd in GITHUB_RUNNER
				// so if it's not present in allowed-domains, traffic to it will get blocked
				// since it is called by default service, we don't need to add it to annotations
				// call to docker.io is made by docker. It makes a DNS resolution call, but does not
				// make a connection to it. This leads to an unnecessary annotation.
				if !strings.Contains(domain, "api.snapcraft.io") && !strings.Contains(domain, "docker.io") {
					go WriteAnnotation(fmt.Sprintf("StepSecurity Harden Runner: DNS resolution for domain %s was blocked. This domain is not in the list of allowed-endpoints.", domain))
				}

				// return an ip address, so calling process calls the ip address
				// the call will be blocked by the firewall
				proxy.Cache.Set(domain, &Answer{Name: domain, TTL: math.MaxInt32, Data: StepSecuritySinkHoleIPAddress}, false)

				go proxy.ApiClient.sendDNSRecord(proxy.CorrelationId, proxy.Repo, domain, StepSecuritySinkHoleIPAddress)

				return StepSecuritySinkHoleIPAddress, nil
			}
		}
	}

	answer, err := proxy.ResolveDomain(domain)
	if err != nil {
		go WriteLog(fmt.Sprintf("unable to resolve domain: %s err: %v", domain, err))
		return "", fmt.Errorf("error in response from dns.google %v", err)
	}

	if matchesAnyWildcard {
		if err := InsertAllowRule(proxy.Iptables, answer.Data, wildcardPort); err != nil {
			WriteLog(fmt.Sprintf("Error setting firewall for wildcard domain %s:  %v", domain, err))
		}
	}

	proxy.Cache.Set(domain, answer, matchesAnyWildcard)

	go WriteLog(fmt.Sprintf("domain resolved: %s, ip address: %s, TTL: %d", domain, answer.Data, answer.TTL))

	go proxy.ApiClient.sendDNSRecord(proxy.CorrelationId, proxy.Repo, domain, answer.Data)

	return answer.Data, nil

}

func (proxy *DNSProxy) matchAnyWildcard(domain string) (bool, string) {
	for wildcard := range proxy.WildCardEndpoints {
		if matchWildcardDomain(wildcard, domain) {
			return true, fmt.Sprintf("%v", proxy.WildCardEndpoints[wildcard][0].port)
		}
	}
	return false, ""
}

func (proxy *DNSProxy) processTypeA(q *dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {

	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}
	domains := map[string]string{
		"dns.google.":         "8.8.8.8",
		"cloudflare-dns.com.": "1.1.1.1",
	}

	if ip, ok := domains[q.Name]; ok {
		rr, err := dns.NewRR(fmt.Sprintf("%s IN A %s", q.Name, ip))

		if err != nil {
			return nil, err
		}

		proxy.Cache.Set(q.Name, &Answer{Name: q.Name, TTL: math.MaxInt32, Data: ip}, false)

		return &rr, nil
	}

	// Azure VM sometimes sends domain name with suffix of internal.cloudapp.net.
	if strings.HasSuffix(q.Name, ".internal.cloudapp.net.") {
		q.Name = getDomainFromCloudAppFormat(q.Name)
	}

	ip, err := proxy.getIPByDomain(q.Name)

	if err != nil {
		return nil, err
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s IN A %s", q.Name, ip))

	if err != nil {
		return nil, err
	}

	proxy.SetReverseIPLookup(q.Name, ip)

	return &rr, nil
}

func startDNSServer(dnsProxy *DNSProxy, server DNSServer, errc chan error) {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		switch r.Opcode {
		case dns.OpcodeQuery:
			m, err := dnsProxy.getResponse(r)
			if err != nil {
				m.SetReply(r)
				w.WriteMsg(m)
				return
			}

			m.SetReply(r)
			w.WriteMsg(m)
		}
	})

	err := server.ListenAndServe()

	if err != nil {
		errc <- errors.Wrap(err, fmt.Sprintf("failed to listen on %v", server))
	}

}

func matchWildcardDomain(pattern, target string) bool {
	// pattern: *.github.com
	// target: h0x0er.github.com

	result := false

	splits := strings.Split(pattern, "*")
	if splits[0] != "" {
		result = strings.HasPrefix(target, splits[0]) && strings.HasSuffix(target, splits[1])
	} else {
		result = strings.HasSuffix(target, splits[1])
	}

	return result

}
