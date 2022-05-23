DDNS with Cloudflare and Pushover
==========
A commandline tool for dynamic updating DNS record. If ip address has changed, it sends notification with pushover.

## Usage
```
Usage:
  ddns-pushover [OPTIONS]

Application Options:
  -n, --dns=            DNS to use to resolve www.cloudflare.com. For example: https://1.0.0.1/dns-query, tls://8.8.8.8 . If empty, use the system default.
  -o, --host=           Force using host address as cloudflare's host (www.cloudflare.com). If empty, host is resolved with dns.
  -t, --token=          Cloudflare API token.
  -z, --zone=           Cloudflare zone identifier.
  -4, --ipv4=           DNS A record id to update. At least ONE A or AAAA record must be specified.
  -6, --ipv6=           DNS AAAA record id to update. At least ONE A or AAAA record must be specified.
  -p, --pushover-token= Pushover Token.
  -u, --pushover-user=  Pushover User.
  -d, --device=         Pushover devices.
```

__Example:__
```bash
$ ./ddns-pushover -n https://1.0.0.1/dns-query -t 93z90rW6w -z 4fb1e0b5b61 -p ad32kzy -u ut3nabzk6 -4 6ce06e -4 48eda -6 a50fe3 -6 5e62c9
```
