SANCrawler
===

Enumerates subdomains and top level domains using SSL certificate meta-data.

---
How to build (requires golang):
---

make

[If no golang installed, get it first]

apt-get install golang


---
How to run
---

1. Acquire a seed value. You must browse to an HTTPS enabled site of the target and examine the X.509
   certificate. Extract the "Organization" field. For example, https://www.google.com/ has the
   seed value of: Google Trust Services

2. Invoke as follows (respect the quotes):

./sancrawler -o "SEED"

Ex:

./sancrawler -o "Google Trust Services"

