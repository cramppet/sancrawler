# SANCrawler

Enumerates subdomains and top level domains using X509 certificate data fields.

## How to build 

`sudo apt-get install golang`

`make`

## How to run

1. Acquire a seed value. You must browse to an HTTPS enabled site of the target and examine the X.509
   certificate. Extract the "Organization" field. For example, https://www.google.com/ has the
   seed value of: Google Trust Services

2. Invoke as follows (respect the quotes):

  `./sancrawler -s "Google Trust Services"`

