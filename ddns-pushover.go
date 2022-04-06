package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

var ErrNotFound = errors.New("IP address not found.")

func ResolveCFAddr(ipv6 bool) (string, error) {
	u, err := upstream.AddressToUpstream("https://1.0.0.1/dns-query", &upstream.Options{
		Timeout:            time.Duration(30) * time.Second,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return "", err
	}
	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	var qType uint16
	if ipv6 {
		qType = dns.TypeAAAA
	} else {
		qType = dns.TypeA
	}
	req.Question = []dns.Question{
		{Name: "www.cloudflare.com.", Qtype: qType, Qclass: dns.ClassINET},
	}
	log.Default().Println("Resolving www.cloudflare.com...")
	reply, err := u.Exchange(&req)
	if err != nil {
		return "", err
	}
	log.Default().Printf("Resolved: %s\n", reply.String())
	if len(reply.Answer) > 0 {
		answer := reply.Answer[0].String()
		fields := strings.Split(answer, "\t")
		ip := fields[len(fields)-1]
		return ip, nil
	}

	return "", errors.New("not found")
}

func GetIP(resolve bool, ipv6 bool) (string, error) {
	var host string = "www.cloudflare.com"

	if resolve {
		ip, err := ResolveCFAddr(ipv6)
		if err != nil {
			return "", err
		}
		host = ip
	}

	api := fmt.Sprintf("https://%s/cdn-cgi/trace", host)
	req, _ := http.NewRequest("GET", api, nil)
	req.Host = "www.cloudflare.com"

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "www.cloudflare.com",
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)
	lines := strings.Split(bodyStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "ip") {
			row := strings.Split(line, "=")
			if len(row) > 1 {
				return row[1], nil
			}
		}
	}
	return "", errors.New("not found")
}

func main() {
	ip, err := GetIP(true, false)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(ip)

}
