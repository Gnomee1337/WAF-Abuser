# WAF-Abuser
WAF-Abuser is a enumeration tool that uses services with history records to discover direct IP address behind WAF (CloudFlare, Incapsula, Akamai, etc)

![WAF-Abuser-overview](https://i.imgur.com/RLWSfxC.jpeg)

<sub>Inspired by: https://github.com/vincentcox/bypass-firewalls-by-DNS-history/ and crimeflare</sub>

# Algorithm:
1. Discover (sub)domains related to the given domain
2. Collect IP address history for every found (sub)domain
3. Excludes WAF associated IP addresses
4. Compare HTML responses for similarity to the original host
5. Output results

# Setup:
```
$ pip install -r requirements.txt
```

# Usage:
```
$ python3 waf-abuser.py --help

usage: waf-abuser.py -d "example.com"

options:
  -h, --help    show this help message and exit
  -d "domain", --domain "domain"    Specify the FQDN/Domain for searches
  -f [FILE...], --file [FILE...]    Specify the file with domains for searches

Optional arguments:
  --similarity-rate [0-100]    Minimum passing percentage for page similarity. (Default value: 70)
  --domains-only    Find only domains and subdomains.
```

# Services in use:
### (Sub)domain Gathering:
- [x] [DNSdumpster](https://dnsdumpster.com/)
- [x] [CertSpotter](https://sslmate.com/certspotter/) (Limit of 100 API calls per hour)
- [x] [API-HackerTarget](https://hackertarget.com/)  (Limit of 50 API calls per day)
- [x] [crt.sh](https://crt.sh/)

### IP Gathering
- [x] [ViewDNS.info](https://viewdns.info/)

# Project structure:
```
conf/                            - Configs for API Keys
output/                          - Final positive results are duplicated in this directory

data/PublicWAFs.txt              - WAF IP ranges in CIDR
data/cdn-ns.json                 - WAFs

modules/subdomain_gathering.py   - Find (sub)domains
modules/ip_gathering.py          - Find IPs in history
modules/utility.py               - Auxiliary functions

cache/                           - Directory for cached intermediate results (.json, .txt, .html)
```

# References
- https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/
- https://github.com/vincentcox/bypass-firewalls-by-DNS-history/
- https://dualuse.io/blog/curryfinger/
- https://github.com/Warflop/cloudbunny/
