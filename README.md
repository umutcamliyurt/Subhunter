# Subhunter
## A fast subdomain takeover tool

<img src="banner.png" width="1300">

## Description:

Subdomain takeover is a common vulnerability that allows an attacker to gain control over a subdomain of a target domain and redirect users intended for an organization's domain to a website that performs malicious activities, such as phishing campaigns,
stealing user cookies, etc. It occurs when an attacker gains control over a subdomain of a target domain.
Typically, this happens when the subdomain has a CNAME in the DNS, but no host is providing content for it.
Subhunter takes a given list of subdomains and scans them to check this vulnerability.

## Features:

- Auto update
- Uses random user agents
- Built in Go
- Uses a fork of fingerprint data from well known sources ([can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md))

## Installation:

### Option 1:

[Download](https://github.com/Nemesis0U/Subhunter/releases) from releases

### Option 2:
Build from source:

    $ git clone https://github.com/Nemesis0U/Subhunter.git
    $ go build subhunter.go

## Usage:

### Options:

```
Usage of subhunter:
  -l string
    	File including a list of hosts to scan
  -o string
    	File to save results
  -t int
    	Number of threads for scanning (default 50)
  -timeout int
    	Timeout in seconds (default 20)
```

### Demo (Added fake fingerprint for POC):

```
./Subhunter -l subdomains.txt -o test.txt

  ____            _       _                       _
 / ___|   _   _  | |__   | |__    _   _   _ __   | |_    ___   _ __
 \___ \  | | | | | '_ \  | '_ \  | | | | | '_ \  | __|  / _ \ | '__|
  ___) | | |_| | | |_) | | | | | | |_| | | | | | | |_  |  __/ | |
 |____/   \__,_| |_.__/  |_| |_|  \__,_| |_| |_|  \__|  \___| |_|


A fast subdomain takeover tool

Created by Nemesis

Loaded 88 fingerprints for current scan

-----------------------------------------------------------------------------

[+] Nothing found at www.ubereats.com: Not Vulnerable
[+] Nothing found at testauth.ubereats.com: Not Vulnerable
[+] Nothing found at apple-maps-app-clip.ubereats.com: Not Vulnerable
[+] Nothing found at about.ubereats.com: Not Vulnerable
[+] Nothing found at beta.ubereats.com: Not Vulnerable
[+] Nothing found at ewp.ubereats.com: Not Vulnerable
[+] Nothing found at edgetest.ubereats.com: Not Vulnerable
[+] Nothing found at guest.ubereats.com: Not Vulnerable
[+] Google Cloud: Possible takeover found at testauth.ubereats.com: Vulnerable
[+] Nothing found at info.ubereats.com: Not Vulnerable
[+] Nothing found at learn.ubereats.com: Not Vulnerable
[+] Nothing found at merchants.ubereats.com: Not Vulnerable
[+] Nothing found at guest-beta.ubereats.com: Not Vulnerable
[+] Nothing found at merchant-help.ubereats.com: Not Vulnerable
[+] Nothing found at merchants-beta.ubereats.com: Not Vulnerable
[+] Nothing found at merchants-staging.ubereats.com: Not Vulnerable
[+] Nothing found at messages.ubereats.com: Not Vulnerable
[+] Nothing found at order.ubereats.com: Not Vulnerable
[+] Nothing found at restaurants.ubereats.com: Not Vulnerable
[+] Nothing found at payments.ubereats.com: Not Vulnerable
[+] Nothing found at static.ubereats.com: Not Vulnerable

Subhunter exiting...
Results written to test.txt


```

