package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)


func GetIP() (string, error) {
	req, _ := http.NewRequest("GET", "https://104.16.160.24/cdn-cgi/trace", nil)
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
	lines := strings.Split(bodyStr,"\n")
	for _,line := range lines {
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
	ip, err := GetIP()
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(ip)
	
}