package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

var ErrNotFound = errors.New("IP address not found.")
var DefaultUpstreamDNS = "https://1.0.0.1/dns-query"

// Resolve www.cloudflare.com using upstream_dns
func ResolveCFAddr(upstream_dns string, ipv6 bool) (string, error) {

	if upstream_dns == "" {
		ips, err := net.LookupIP("www.cloudflare.com")
		if err != nil {
			log.Fatal("Cannot lookup www.cloudflare.com:", err.Error())
		}
		for _, ip := range ips {
			ip4 := ip.To4()
			if !ipv6 && ip4 != nil {
				return ip4.String(), nil
			} else if ipv6 && ip4 == nil {
				return "[" + ip.String() + "]", nil
			}
		}
		return "", ErrNotFound
	}

	u, err := upstream.AddressToUpstream(upstream_dns, &upstream.Options{
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

	reply, err := u.Exchange(&req)
	if err != nil {
		return "", err
	}

	if len(reply.Answer) > 0 {
		answer := reply.Answer[0].String()
		fields := strings.Split(answer, "\t")
		ip := fields[len(fields)-1]
		if ipv6 {
			ip = "[" + ip + "]"
		}
		return ip, nil
	}

	return "", ErrNotFound
}

func GetIP(host string) (string, error) {
	if host == "" {
		host = "www.cloudflare.com"
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
	return "", ErrNotFound
}

type DNSRecordDetails struct {
	Success  bool
	Errors   []string
	Messages []string
	Result   struct {
		Id         string
		Type       string
		Name       string
		Content    string
		Proxiable  bool
		Proxied    bool
		TTL        uint32 `json:"ttl"`
		Locked     bool
		ZoneId     string    `json:"zone_id"`
		ZoneName   string    `json:"zone_name"`
		CreatedOn  time.Time `json:"created_on"`
		ModifiedOn time.Time `json:"modified_on"`
		Data       map[string]interface{}
		Meta       struct {
			AutoAdded bool
			Source    string
		}
	}
}

func UpdateDNS(cfToken string, zoneId string, recordId string, content string, client *http.Client) (string, error) {

	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	req.Header.Add("Authorization", "Bearer "+cfToken)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Errored when sending request to the server:", err.Error())
		return "", err
	}

	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	//log.Printf("%s - %s\n", resp.Status, string(responseBody))
	ret := DNSRecordDetails{}
	if err = json.Unmarshal(responseBody, &ret); err != nil {
		return "", err
	}
	originalIP := ret.Result.Content
	log.Println("Original IP:", originalIP)

	values := map[string]string{"content": content}
	jsonData, err := json.Marshal(values)
	req2, err := http.NewRequest(http.MethodPatch, uri, bytes.NewBuffer(jsonData))
	req2.Header.Add("Authorization", "Bearer "+cfToken)
	req2.Header.Add("Content-Type", "application/json")
	if err != nil {
		return "", err
	}

	resp2, err := client.Do(req2)
	if err != nil {
		log.Println("Errored when sending request to the server:", err.Error())
		return "", err
	}
	defer resp2.Body.Close()
	responseBody, err = ioutil.ReadAll(resp2.Body)
	if err != nil {
		return "", err
	}
	//log.Printf("%s - %s\n", resp2.Status, string(responseBody))
	if err = json.Unmarshal(responseBody, &ret); err != nil {
		return "", err
	}
	if !ret.Success {
		return originalIP, errors.New(strings.Join(ret.Errors, "\n"))
	}

	return originalIP, nil
}

func Notify(token string, user string, device string, content string) error {
	_, err := http.PostForm("https://api.pushover.net/1/messages.json", url.Values{
		"token":   {token},
		"user":    {user},
		"title":   {"Home IP Updated"},
		"message": {content},
		"device":  {device},
	})
	if err != nil {
		return err
	}
	//defer resp.Body.Close()
	//responseBody, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	return err
	//}
	//log.Println(string(responseBody))
	log.Println("Notification sent.")
	return nil
}

var opts struct {
	DNS             string   `short:"n" long:"dns"  description:"DNS to use. If empty, use system default. For example: https://1.0.0.1/dns-query, tls://8.8.8.8"`
	Host            string   `short:"h" long:"host" description:"Force using host as cloudflare's host. If empty, host is resolved with dns."`
	CFToken         string   `short:"t" long:"token" description:"Cloudflare API token." required:"true"`
	CFZone          string   `short:"z" long:"zone" description:"Cloudflare zone identifier." required:"true"`
	DNS4RecordIDs   []string `short:"4" long:"ipv4" description:"DNS A record id to update. At least ONE A or AAAA record must be specified."`
	DNS6RecordIDs   []string `short:"6" long:"ipv6" description:"DNS AAAA record id to update. At least ONE A or AAAA record must be specified."`
	PushOverToken   string   `short:"p" long:"ptoken" description:"Pushover Token."`
	PushOverUser    string   `short:"u" long:"puser" description:"Pushover User."`
	PushOverDevices []string `short:"d" long:"device" description:"Pushover devices."`
}

func main() {
	_, err := flags.Parse(&opts)
	parser := flags.NewParser(&opts, flags.Default)

	if len(opts.DNS4RecordIDs) == 0 && len(opts.DNS6RecordIDs) == 0 {
		parser.WriteHelp(os.Stderr)
		os.Exit(1)
	}

	ip4, ip6 := "", ""
	if len(opts.DNS4RecordIDs) > 0 {
		if opts.Host != "" {
			ip4, err = GetIP(opts.Host)
		} else {
			log.Println("Resolving www.cloudflare.com in ipv4...")
			host, err := ResolveCFAddr(opts.DNS, false)
			if err != nil {
				log.Println("Resolve Cloudflare ipv4 host error:", err.Error())
			} else {
				log.Println("Resolved Cloudflare host:", host)
				ip4, err = GetIP(host)
			}
		}
		if err != nil {
			log.Println("Get IPv4 Error:", err.Error())
		}
		if ip := net.ParseIP(ip4); ip != nil {
			log.Println("External IPv4:", ip4)
			if ip.To4() == nil {
				log.Println("Not a valid IPv4 address.")
				ip4 = ""
			}
		}
	}

	if len(opts.DNS6RecordIDs) > 0 {
		if opts.Host != "" {
			ip6, err = GetIP(opts.Host)
		} else {
			log.Default().Println("Resolving www.cloudflare.com in ipv6...")
			host, err := ResolveCFAddr(opts.DNS, true)
			if err != nil {
				log.Println("Resolve Cloudflare ipv6 host error:", err.Error())
			} else {
				log.Println("Resolved Cloudflare host:", host)
				ip6, err = GetIP(host)
			}
		}
		if err != nil {
			log.Println("Get IPv6 Error:", err.Error())
		}
		if ip := net.ParseIP(ip6); ip != nil {
			log.Println("External IPv6:", ip6)
			if ip.To4() != nil {
				log.Println("Not a valid IPv6 address.")
				ip6 = ""
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}

	originalIPs := make(map[string]bool)

	if ip4 != "" {
		for _, record := range opts.DNS4RecordIDs {
			oip, err := UpdateDNS(opts.CFToken, opts.CFZone, record, ip4, client)
			if err != nil {
				log.Println("Update DNS error:", err)
				break
			}
			if oip != "" && !originalIPs[oip] {
				originalIPs[oip] = true
			}
		}
	}
	if ip6 != "" {
		for _, record := range opts.DNS6RecordIDs {
			oip, err := UpdateDNS(opts.CFToken, opts.CFZone, record, ip6, client)
			if err != nil {
				log.Println("Update DNS error:", err)
				break
			}
			if oip != "" && !originalIPs[oip] {
				originalIPs[oip] = true
			}
		}
	}

	if (ip4 != "" && !originalIPs[ip4]) || (ip6 != "" && !originalIPs[ip6]) {
		keys := make([]string, 0, len(originalIPs))
		for k := range originalIPs {
			keys = append(keys, k)
		}

		msg := fmt.Sprintf("%s\n\nOriginal:\n%s", strings.Join([]string{ip4, ip6}, "\n"), strings.Join(keys, "\n"))
		Notify(opts.PushOverToken, opts.PushOverUser, strings.Join(opts.PushOverDevices, ","), msg)
	} else {
		log.Println("IPs stay unchanged.")
	}
}
