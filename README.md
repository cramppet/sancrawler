# SANCrawler

Enumerate subdomains and top level domains using X509 certificate data fields.

## What is SANCrawler

SANCrawler is a script that uses the crt.sh service to discover linked top level
domains and subdomains of an organization. SANCrawler must be used with a valid
organization name taken from an x509 certificate. See the "How to run" section
for more.

SANCrawler will output results in the following JSON schema:

```json
{
  "known_domains": [],

  "possible_orgs": []
}
```

Where `known_domains` is a list containing all of the discovered linked domains and subdomains as strings,
and `possible_orgs` is list containing possible organization names / organizational unit names which 
can be used with SANCrawler again if desired.

## How to run

1. Acquire a seed value. You must browse to an HTTPS enabled site of the target and examine the X.509
   certificate. Extract the "Organization" or "Organizational Unit" field. For example, 
   https://www.google.com/ has the seed value of: Google Trust Services

2. Invoke as follows: `python sancrawler.py -s "Google Trust Services"`

