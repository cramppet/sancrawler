package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/lib/pq"
	"log"
	"strings"
)

/* run_query => runs a SQL query against the crt.sh SQL instance to extract
 * all common names and subject alternative names from every certificate
 * which matches the specified identifier on either the "Organization" or
 * "Organizational Unit" field in the X509 data.
 *
 * Returns: map[string]int => a hashmap containing the results, a hashmap
 * is used as a simple mechanism to keep a uniq list.
 */
func run_query(identifier string) map[string]int {
	conn := "postgres://guest@crt.sh/certwatch?sslmode=disable"
	db, err := sql.Open("postgres", conn)
	query := `
        SELECT ci.ISSUER_CA_ID,
               ci.NAME_VALUE NAME_VALUE,
               min(c.ID) MIN_CERT_ID,
               x509_altNames(c.CERTIFICATE, 2, TRUE) SAN_NAME,
               x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) COMMON_NAME
          FROM ca,
               ct_log_entry ctle,
               certificate_identity ci,
               certificate c
          WHERE ci.ISSUER_CA_ID = ca.ID
                AND c.ID = ctle.CERTIFICATE_ID
                AND ci.CERTIFICATE_ID = c.ID
                AND ((lower(ci.NAME_VALUE) LIKE $1 || '%' AND ci.NAME_TYPE = 'organizationName')
                      OR (lower(ci.NAME_VALUE) LIKE $1 || '%' AND ci.NAME_TYPE = 'organizationalUnitName'))
          GROUP BY ci.ISSUER_CA_ID, c.ID, NAME_VALUE, COMMON_NAME, SAN_NAME;
        `

	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query(query, identifier)
	known := make(map[string]int)

	if err != nil {
		log.Fatal(err)
	} else {
		for rows.Next() {
			var ca_id string
			var cert_id string
			var name_value string
			var common_name string
			var san_name string

			err = rows.Scan(&ca_id, &cert_id, &name_value, &common_name, &san_name)

			if err == nil {
				known[san_name] = 0
				known[common_name] = 0
			} else {
				log.Fatal(err)
			}
		}
	}

	rows.Close()
	db.Close()
	return known
}

func main() {
	var org = flag.String("s", "", "Seed string")
	flag.Parse()

	if *org != "" {
		art := `
__________
\\        | S A N   C R A W L E R
 \\       | Find subdomains with X509 metadata
  \\@@@@@@|   @cramppet
  `

		fmt.Println(art)

		org_lower := strings.ToLower(*org)
		results := run_query(org_lower)

		for res, _ := range results {
			fmt.Println(res)
		}
	}
}
