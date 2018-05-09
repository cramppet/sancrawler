package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const (
	CRT_SH_BASE   = "https://crt.sh/"
	CRT_SH_ORG    = "?O="
	CRT_SH_DOMAIN = "?q="
	NUM_CRAWLERS  = 50
	MAX_CHAN_LEN  = 1000
)

var NAME_CHAN chan string
var ID_CHAN chan string
var DONE_CHAN chan bool

func CrawlerFn() {
	// YES. I'll get an XML parser when I need one.
	// https://stackoverflow.com/questions/1732348/regex-match-open-tags-except-xhtml-self-contained-tags
	RE_COMMON_NAMES := regexp.MustCompile(`(?i)<br>commonName=.*?<br>`)
	RE_SAN := regexp.MustCompile(`(?i)<br>DNS:.*?<br>`)

	for {
		select {
		case <-DONE_CHAN:
			return

		case id := <-ID_CHAN:
			url := CRT_SH_BASE + id
			res, err := http.Get(url)

			if err != nil {
				panic(err)
			}

			body, _ := ioutil.ReadAll(res.Body)
			bodys := strings.Replace(string(body), "&nbsp;", "", -1)
			res.Body.Close()

			common_names := RE_COMMON_NAMES.FindAllString(bodys, -1)
			san := RE_SAN.FindAllString(bodys, -1)

			// Ignore the first common name since that is the common name of the issuer.
			if common_names != nil {
				for i := 1; i < len(common_names); i += 1 {
					temp := common_names[i]
					temp = strings.Replace(temp, "<BR>", "", -1)
					temp = strings.Replace(temp, "commonName=", "", -1)
					NAME_CHAN <- temp
				}
			}

			if san != nil {
				for i := 0; i < len(san); i += 1 {
					temp := san[i]
					temp = strings.Replace(temp, "<BR>", "", -1)
					temp = strings.Replace(temp, "DNS:", "", -1)
					NAME_CHAN <- temp
				}
			}
		}
	}
}

func GetDomainsByOrg(orgname string) {
	orgname = strings.Replace(orgname, " ", "+", -1)
	url := CRT_SH_BASE + CRT_SH_ORG + orgname
	domains_and_subdomains := GetNames(url, true)

	for k, _ := range domains_and_subdomains {
		fmt.Println(k)
	}
}

func GetSubdomainsByDomain(domain string) map[string]int {
	url := CRT_SH_BASE + CRT_SH_DOMAIN + `%25` + domain
	subdomains := GetNames(url, false)
	return subdomains
}

func GetNames(url string, start_crawlers bool) map[string]int {
	RE_ORG_IDS, _ := regexp.Compile(`\?id\=\d+`)
	domains := make(map[string]int)
	res, err := http.Get(url)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	// After we have obtained the list of IDs, extract them
	body, _ := ioutil.ReadAll(res.Body)
	ids := RE_ORG_IDS.FindAllString(string(body), -1)

	// Spawn the crawlers and supply them with the IDs via ID_CHAN
	if start_crawlers {
		for i := 0; i < NUM_CRAWLERS; i += 1 {
			go CrawlerFn()
		}
	}

	for i := 0; i < len(ids); i += 1 {
		select {
		case name := <-NAME_CHAN:
			domains[name] = 0
		case ID_CHAN <- ids[i]:
			continue
		}
	}

	for len(ID_CHAN) > 0 || len(NAME_CHAN) > 0 {
		name := <-NAME_CHAN
		domains[name] = 0
	}

	return domains
}

func print_ascii_art() {
  art := `
  __________
  \\        | S A N   C R A W L E R
   \\       | Find subdomains with X509 metadata
    \\@@@@@@|   @cramppet
  `
  fmt.Println(art)
}

func main() {
	ID_CHAN = make(chan string, MAX_CHAN_LEN)
	NAME_CHAN = make(chan string, MAX_CHAN_LEN)
	DONE_CHAN = make(chan bool, NUM_CRAWLERS)

	var org = flag.String("o", "", "Organization to use as a seed")
	flag.Parse()

	if *org != "" {
                print_ascii_art()
		GetDomainsByOrg(*org)
	}
}

