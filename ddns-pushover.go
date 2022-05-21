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
	"github.com/avast/retry-go"
	"github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

var ErrNotFound = errors.New("IP address not found")

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

func GetExternalIP(host string) (string, error) {
	if host == "" {
		host = "www.cloudflare.com"
	}

	api := fmt.Sprintf("https://%s/cdn-cgi/trace", host)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		return "", err
	}
	req.Host = "www.cloudflare.com"

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "www.cloudflare.com",
			},
		},
	}

	var myIP string = ""

	err = retry.Do(
		func() error {
			resp, err := httpClient.Do(req)
			if err != nil {
				return err
			}

			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf(resp.Status)
			}
			bodyStr := string(body)
			lines := strings.Split(bodyStr, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "ip") {
					row := strings.Split(line, "=")
					if len(row) > 1 {
						myIP = row[1]
						return nil
					}
				}
			}
			return nil
		},
		retry.Attempts(3),
		retry.Delay(1*time.Second),
	)

	// client := hardy.NewClient(httpClient, log.Default()).
	// 	WithMaxRetries(3).
	// 	WithWaitInterval(3 * time.Millisecond).
	// 	WithMultiplier(hardy.DefaultMultiplier).
	// 	WithMaxInterval(3 * time.Second)

	// readerFunc := func(retIP *string) hardy.ReaderFunc {
	// 	return func(response *http.Response) error {
	// 		if response.StatusCode == http.StatusOK {
	// 			defer response.Body.Close()
	// 			body, err := ioutil.ReadAll(response.Body)
	// 			if err != nil {
	// 				return fmt.Errorf(response.Status)
	// 			}
	// 			bodyStr := string(body)
	// 			lines := strings.Split(bodyStr, "\n")
	// 			for _, line := range lines {
	// 				if strings.HasPrefix(line, "ip") {
	// 					row := strings.Split(line, "=")
	// 					if len(row) > 1 {
	// 						*retIP = row[1]
	// 						return nil
	// 					}
	// 				}
	// 			}
	// 		}
	// 		return fmt.Errorf(response.Status)
	// 	}
	// }

	// fallbackFunc := func(retIP *string) hardy.FallbackFunc {
	// 	return func() error {
	// 		*retIP = ""
	// 		return nil
	// 	}
	// }

	// err = client.Try(ctx, req, readerFunc(&myIP), fallbackFunc(&myIP))
	if err != nil {
		return "", ErrNotFound
	}

	return myIP, nil
}

type DNSRecordDetails struct {
	Success bool
	Errors  []struct {
		Code    uint32
		Message string
	}
	Messages   []string
	ResultInfo struct {
		Page       uint32
		PerPage    uint32 `json:"per_page"`
		Count      uint32
		TotalCount uint32 `json:"total_count"`
	} `json:"result_info"`
	Result struct {
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

func GetOriginalIP(cfToken string, zoneId string, recordId string, client *http.Client) (string, error) {
	var myIP string
	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Authorization", "Bearer "+cfToken)

	err = retry.Do(
		func() error {
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			responseBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				//log.Println("Get Original IP read body error:", err)
				return fmt.Errorf("get original IP read body error: %v", err)
			}
			ret := DNSRecordDetails{}
			if err = json.Unmarshal(responseBody, &ret); err != nil {
				//log.Println("Unable to unmarshal response:", string(responseBody))
				return fmt.Errorf("unable to unmarshal reponse: %s \nerror: %v", string(responseBody), err)
			}
			myIP = ret.Result.Content
			return nil
		},
		retry.Attempts(3),
		retry.Delay(1*time.Second),
	)
	if err != nil {
		return "", nil
	}
	return myIP, nil
}

func UpdateRecord(cfToken string, zoneId string, recordId string, content string, client *http.Client) error {
	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)

	values := map[string]string{"content": content}
	jsonData, err := json.Marshal(values)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, uri, bytes.NewBuffer(jsonData))
	req.Header.Add("Authorization", "Bearer "+cfToken)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		log.Println("new request error:", err)
		return err
	}

	err = retry.Do(
		func() error {
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			ret := DNSRecordDetails{}
			responseBody, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("get Original IP read body error: %v", err.Error())
			}

			if err = json.Unmarshal(responseBody, &ret); err != nil {
				log.Println("Unable to unmarshal response:", string(responseBody))
				return nil
			}
			if !ret.Success {
				errs := []string{}
				for i, e := range ret.Errors {
					errs = append(errs, fmt.Sprintf("%d: %s", i+1, e.Message))
				}
				log.Println(strings.Join(errs, "\n"))
				return nil
			}
			return nil
		},
		retry.Attempts(3),
	)
	if err != nil {
		return err
	}
	return nil
}

// type APIService struct {
// 	Client *hardy.Client
// }

// func (s *APIService) GetOrignalIP(ctx context.Context, cfToken string, zoneId string, recordId string) (string, error) {
// 	if s.Client == nil {
// 		return "", fmt.Errorf("no client is given")
// 	}
// 	var myIP string
// 	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)
// 	req, err := http.NewRequest(http.MethodGet, uri, nil)
// 	if err != nil {
// 		return "", err
// 	}
// 	req.Header.Add("Authorization", "Bearer "+cfToken)

// 	readerFunc := func(message *string) hardy.ReaderFunc {
// 		return func(response *http.Response) error {
// 			if response.StatusCode == http.StatusOK {
// 				defer response.Body.Close()
// 				responseBody, err := ioutil.ReadAll(response.Body)
// 				if err != nil {
// 					//log.Println("Get Original IP read body error:", err)
// 					return fmt.Errorf("get original IP read body error: %v", err)
// 				}
// 				ret := DNSRecordDetails{}
// 				if err = json.Unmarshal(responseBody, &ret); err != nil {
// 					//log.Println("Unable to unmarshal response:", string(responseBody))
// 					return fmt.Errorf("unable to unmarshal reponse: %s \nerror: %v", string(responseBody), err)
// 				}
// 				*message = ret.Result.Content
// 				return nil
// 			}
// 			return fmt.Errorf(response.Status)
// 		}
// 	}

// 	fallbackFunc := func(message *string) hardy.FallbackFunc {
// 		return func() error {
// 			*message = "api access error"
// 			return nil
// 		}
// 	}

// 	err = s.Client.Try(ctx, req, readerFunc(&myIP), fallbackFunc(&myIP))
// 	if err != nil {
// 		return myIP, err
// 	}
// 	return myIP, nil
// }

// func (s *APIService) UpdateRecord(ctx context.Context, cfToken string, zoneId string, recordId string, content string) error {
// 	if s.Client == nil {
// 		return fmt.Errorf("no client is given")
// 	}

// 	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)

// 	values := map[string]string{"content": content}
// 	jsonData, err := json.Marshal(values)
// 	if err != nil {
// 		return err
// 	}

// 	req, err := http.NewRequest(http.MethodPatch, uri, bytes.NewBuffer(jsonData))
// 	req.Header.Add("Authorization", "Bearer "+cfToken)
// 	req.Header.Add("Content-Type", "application/json")
// 	if err != nil {
// 		log.Println("new request error:", err)
// 		return err
// 	}

// 	readerFunc := func() hardy.ReaderFunc {
// 		return func(response *http.Response) error {
// 			if response.StatusCode == http.StatusOK {
// 				defer response.Body.Close()
// 				ret := DNSRecordDetails{}
// 				responseBody, err := ioutil.ReadAll(response.Body)
// 				if err != nil {
// 					return fmt.Errorf("get Original IP read body error: %v", err.Error())
// 				}

// 				if err = json.Unmarshal(responseBody, &ret); err != nil {
// 					log.Println("Unable to unmarshal response:", string(responseBody))
// 					return nil
// 				}
// 				if !ret.Success {
// 					errs := []string{}
// 					for i, e := range ret.Errors {
// 						errs = append(errs, fmt.Sprintf("%d: %s", i+1, e.Message))
// 					}
// 					log.Println(strings.Join(errs, "\n"))
// 					return nil
// 				}
// 				return nil
// 			}
// 			return fmt.Errorf(response.Status)
// 		}
// 	}

// 	err = s.Client.Try(ctx, req, readerFunc(), nil)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// func UpdateDNS(cfToken string, zoneId string, recordId string, content string, client *http.Client) (string, error) {

// 	uri := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneId, recordId)
// 	req, err := http.NewRequest(http.MethodGet, uri, nil)
// 	req.Header.Add("Authorization", "Bearer "+cfToken)
// 	if err != nil {
// 		return "", err
// 	}

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		log.Println("Errored when sending request to the server:", err.Error())
// 		return "", err
// 	}

// 	defer resp.Body.Close()
// 	responseBody, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	//log.Printf("%s - %s\n", resp.Status, string(responseBody))
// 	ret := DNSRecordDetails{}
// 	if err = json.Unmarshal(responseBody, &ret); err != nil {
// 		log.Println("Unable to unmarshal response:", string(responseBody))
// 		return "", err
// 	}
// 	originalIP := ret.Result.Content
// 	log.Println("Original IP:", originalIP)

// 	time.Sleep(1 * time.Second)
// 	values := map[string]string{"content": content}
// 	jsonData, err := json.Marshal(values)
// 	if err != nil {
// 		return "", err
// 	}

// 	req2, err := http.NewRequest(http.MethodPatch, uri, bytes.NewBuffer(jsonData))
// 	req2.Header.Add("Authorization", "Bearer "+cfToken)
// 	req2.Header.Add("Content-Type", "application/json")
// 	if err != nil {
// 		return "", err
// 	}

// 	resp2, err := client.Do(req2)
// 	if err != nil {
// 		log.Println("Errored when sending request to the server:", err.Error())
// 		return "", err
// 	}
// 	defer resp2.Body.Close()
// 	responseBody, err = ioutil.ReadAll(resp2.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	//log.Printf("%s - %s\n", resp2.Status, string(responseBody))
// 	if err = json.Unmarshal(responseBody, &ret); err != nil {
// 		log.Println("Unable to unmarshal response:", string(responseBody))
// 		return "", err
// 	}
// 	if !ret.Success {
// 		errs := []string{}
// 		for i, e := range ret.Errors {
// 			errs = append(errs, fmt.Sprintf("%d: %s", i+1, e.Message))
// 		}
// 		return originalIP, errors.New(strings.Join(errs, "\n"))
// 	}

// 	return originalIP, nil
// }

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
			ip4, err = GetExternalIP(opts.Host)
		} else {
			log.Println("Resolving www.cloudflare.com in ipv4...")
			host, err := ResolveCFAddr(opts.DNS, false)
			if err != nil {
				log.Println("Resolve Cloudflare ipv4 host error:", err.Error())
			} else {
				log.Println("Resolved Cloudflare host:", host)
				ip4, err = GetExternalIP(host)
				if err != nil {
					log.Println("Get external IPv4 error:", err)
				}
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
			ip6, err = GetExternalIP(opts.Host)
		} else {
			log.Default().Println("Resolving www.cloudflare.com in ipv6...")
			host, err := ResolveCFAddr(opts.DNS, true)
			if err != nil {
				log.Println("Resolve Cloudflare ipv6 host error:", err.Error())
			} else {
				log.Println("Resolved Cloudflare host:", host)
				ip6, err = GetExternalIP(host)
				if err != nil {
					log.Println("Get external IPv6 error:", err)
				}
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

	httpClient := &http.Client{Timeout: 10 * time.Second}
	// client := hardy.NewClient(httpClient, log.Default()).
	// 	WithMaxRetries(3).
	// 	WithWaitInterval(1 * time.Second).
	// 	WithMultiplier(hardy.DefaultMultiplier).
	// 	WithMaxInterval(3 * time.Second)
	// apiService := &APIService{Client: client}

	originalIPs := make(map[string]bool)

	if ip4 != "" {
		for _, record := range opts.DNS4RecordIDs {
			//oip, err := UpdateDNS(opts.CFToken, opts.CFZone, record, ip4, client)
			//oip, err := apiService.GetOrignalIP(context.Background(), opts.CFToken, opts.CFZone, record)
			oip, err := GetOriginalIP(opts.CFToken, opts.CFZone, record, httpClient)
			if err != nil {
				log.Println("Get original IP error:", err)
			}
			if oip != ip4 {
				//err = apiService.UpdateRecord(context.Background(), opts.CFToken, opts.CFZone, record, ip4)
				err = UpdateRecord(opts.CFToken, opts.CFZone, record, ip4, httpClient)
				if err != nil {
					log.Println("Update DNS error:", err)
					continue
				}

			}
			if oip != "" && !originalIPs[oip] {
				originalIPs[oip] = true
			}
		}
	}
	if ip6 != "" {
		for _, record := range opts.DNS6RecordIDs {
			//oip, err := apiService.GetOrignalIP(context.Background(), opts.CFToken, opts.CFZone, record)
			oip, err := GetOriginalIP(opts.CFToken, opts.CFZone, record, httpClient)
			if err != nil {
				log.Println("Get original IP error:", err)
			}
			if oip != ip4 {
				//err = apiService.UpdateRecord(context.Background(), opts.CFToken, opts.CFZone, record, ip6)
				err = UpdateRecord(opts.CFToken, opts.CFZone, record, ip6, httpClient)
				if err != nil {
					log.Println("Update DNS error:", err)
					continue
				}
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

		msg := fmt.Sprintf("%s\n\nOriginal:\n%s", strings.Trim(strings.Join([]string{ip4, ip6}, "\n"), "\n"), strings.Join(keys, "\n"))
		log.Println("msg:\n", msg)
		if opts.PushOverToken != "" && opts.PushOverUser != "" {
			Notify(opts.PushOverToken, opts.PushOverUser, strings.Join(opts.PushOverDevices, ","), msg)
		}
	} else {
		log.Println("IPs stay unchanged.")
	}
}
