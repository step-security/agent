package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

type DNSProxy struct {
	Cache            *Cache
	CorrelationId    string
	Repo             string
	ApiClient        *ApiClient
	EgressPolicy     string
	AllowedEndpoints []Endpoint
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

func (proxy *DNSProxy) processOtherTypes(q *dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	return nil, fmt.Errorf("not found")
}

func (proxy *DNSProxy) isAllowedDomain(domain string) bool {
	for _, endpoint := range proxy.AllowedEndpoints {
		if dns.Fqdn(endpoint.domainName) == dns.Fqdn(domain) {
			return true
		}
	}

	return false
}

func (proxy *DNSProxy) getIPByDomain(domain string) (string, error) {
	domain = dns.Fqdn(domain)
	cacheMsg, found := proxy.Cache.Get(domain)

	if found {
		return cacheMsg.(string), nil
	}

	if proxy.EgressPolicy == EgressPolicyBlock {
		if !proxy.isAllowedDomain(domain) {
			go writeLog(fmt.Sprintf("domain not allowed: %s", domain))
			return "", fmt.Errorf("domain not allowed %s", domain)
		}
	}

	url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=a", domain)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error in response from dns.google %v", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("error in response from dns.google %v", err)
	}

	var dnsReponse DNSResponse

	err = json.Unmarshal([]byte(body), &dnsReponse)

	if err != nil {
		return "", fmt.Errorf("error in response from dns.google %v", err)
	}

	for _, answer := range dnsReponse.Answer {
		if answer.Type == 1 {
			proxy.Cache.Set(domain, answer.Data)

			go writeLog(fmt.Sprintf("domain resolved: %s, ip address: %s", domain, answer.Data))

			go proxy.ApiClient.sendDNSRecord(proxy.CorrelationId, proxy.Repo, domain, answer.Data)

			return answer.Data, nil
		}
	}

	return "", fmt.Errorf("not resolved")
}

func (proxy *DNSProxy) processTypeA(q *dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {

	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	if q.Name == "dns.google." {
		rr, err := dns.NewRR("dns.google. IN A 8.8.8.8")

		if err != nil {
			return nil, err
		}

		proxy.Cache.Set(q.Name, &rr)

		return &rr, nil
	}

	ip, err := proxy.getIPByDomain(q.Name)

	if err != nil {
		return nil, err
	}

	rr, err := dns.NewRR(fmt.Sprintf("%s IN A %s", q.Name, ip))

	if err != nil {
		return nil, err
	}

	return &rr, nil

}

func startDNSServer(dnsProxy DNSProxy, server DNSServer, errc chan error) {
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
