#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import re
import json
import subprocess
import os

import psycopg2
import whois


# An ASCII adaptation of
# https://www.geek.com/wp-content/uploads/2011/06/sandcrawler-625x352.jpg
BANNER = r'''
     _______.     ___      .__   __.   ______ .______          ___   ____    __    ____  __       _______ .______      
    /       |    /   \     |  \ |  |  /      ||   _  \        /   \  \   \  /  \  /   / |  |     |   ____||   _  \     
   |   (----`   /  ^  \    |   \|  | |  ,----'|  |_)  |      /  ^  \  \   \/    \/   /  |  |     |  |__   |  |_)  |    
    \   \      /  /_\  \   |  . `  | |  |     |      /      /  /_\  \  \            /   |  |     |   __|  |      /     
.----)   |    /  _____  \  |  |\   | |  `----.|  |\  \----./  _____  \  \    /\    /    |  `----.|  |____ |  |\  \----.
|_______/    /__/     \__\ |__| \__|  \______|| _| `._____/__/     \__\  \__/  \__/     |_______||_______|| _| `._____|
                                                                                                                       

      .%&&&&%%%##(                                         
       &&&&&%%%%&%%%%##%%%/(##(/(                          
       .&&&&%%%%%%%%#%##(#**#/*((%(((((###((*              
        *&&&&%%&%%%#%###((/((*(/*(((/#/(//((####((((       
         &&&&%%####(###/#%((((((*(((((#(###%((((((((       
          &&&%###########%.,###((((((((((#((((((((#(       
           %%%#########%%((((((#(##(%####(((((##((       
           %%%%%%%##,####%(((((/(#((%#&(((#####((        
            %%%&%%%#######(((((((###%%%%%%%(#(((%        
             %%&%&%%%%#####((((((###%##%####%##        
              &%%&%%%####%#####(####################       
..............%&&&%%&&%##%&##(#%%#((%########%%## .......
............... &&&. &%#####%%##%%%%&&@&&&%#####%..........
................&&&&@%%%%%#(((#(((%#&&&&%%########.........
...................%&&&&%##%%###%##,,,,,/%%%#(#(*..........
'''


# As of 5/24/2018 these CA's have collectively issued approximately
# 457,840,000 X509 certificates. They are useful so we can avoid
# false positives.
KNOWN_CA_ORGS = [
    "Let's Encrypt"
    "cPanel, Inc."
    "COMODO CA Limited"
    "GoDaddy.com, Inc."
    "DigiCert Inc"
    "Symantec Corporation"
    "GlobalSign nv-sa"
    "GeoTrust Inc."
    "CloudFlare, Inc."
    "LANCOM Systems"
    "Western Digital Technologies"
    "LANCOM Systems GmbH"
    "StartCom Ltd."
    "D-LINK"
    "GeoTrust, Inc."
    "Ubiquiti Networks Inc."
    "SomeOrganization"
    "VeriSign, Inc."
    "Technicolor"
    "TrustAsia Technologies, Inc."
]


# Query the crt.sh looking for subdomains of a given top level domain.
# Additionally, we grab the certificate's organizationalName and
# organizationalUnitName. We use those later, to look for potentially more seed
# values to use.
def get_tld_linked_orgs(cur, tld):
    ret = []
    transformed = '%%.' + tld
    subdomain_query = '''
    SELECT ci.ISSUER_CA_ID,
        ci.NAME_VALUE NAME_VALUE,
        x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) ORG_NAME,
        x509_nameAttributes(c.CERTIFICATE, 'organizationalUnitName', TRUE) OU_NAME
    FROM ca,
        ct_log_entry ctle,
        certificate_identity ci,
        certificate c
    WHERE ci.ISSUER_CA_ID = ca.ID
        AND c.ID = ctle.CERTIFICATE_ID
        AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower(%s))
        AND ci.CERTIFICATE_ID = c.ID
    GROUP BY c.ID, ci.ISSUER_CA_ID, NAME_VALUE, ORG_NAME, OU_NAME
    '''
    try:
        cur.execute(subdomain_query, (transformed,))
        for record in cur:
            if record[2] and not record[2].endswith(tld):
                ret.append(record[2])
            if record[3] and not record[3].endswith(tld):
                ret.append(record[3])
    except psycopg2.ProgrammingError as ex:
        print 'Programming error caught: '
        print str(ex)
    return ret


# Query the crt.sh postgresql instance looking for shared organizationName or
# organizationalUnitName. Return the domains/subdomains in one list as strs.
def get_x509_linked_tlds(cur, org):
    ret = []
    transformed = org + '%'
    linked_tld_query = '''
    SELECT ci.ISSUER_CA_ID,
        ci.NAME_VALUE NAME_VALUE,
        x509_altNames(c.CERTIFICATE, 2, TRUE) SAN_NAME,
        x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) COMMON_NAME
    FROM ca,
        ct_log_entry ctle,
        certificate_identity ci,
        certificate c
    WHERE ci.ISSUER_CA_ID = ca.ID
        AND c.ID = ctle.CERTIFICATE_ID
        AND ci.CERTIFICATE_ID = c.ID
        AND ((lower(ci.NAME_VALUE) LIKE lower(%s) AND ci.NAME_TYPE = 'organizationName')
                OR (lower(ci.NAME_VALUE) LIKE lower(%s) AND ci.NAME_TYPE = 'organizationalUnitName'))
    GROUP BY ci.ISSUER_CA_ID, c.ID, NAME_VALUE, COMMON_NAME, SAN_NAME;
    '''
    try:
        cur.execute(linked_tld_query, (transformed, transformed))
        for record in cur:
            if record[2]:
                ret.append(record[2])
            if record[3]:
                ret.append(record[3])
        ret = list(set(ret))
    except psycopg2.ProgrammingError as ex:
        print 'Programming error caught: '
        print str(ex)
    return ret


# An attempt at performing top level domain extraction from x509 cert data.
# See: https://stackoverflow.com/a/1066947
def extract_tld(fqdn):
    parts = fqdn.split('.')
    common_tld = ['co','net','org','com']
    if len(parts) == 1:
        return ''
    if len(parts) <= 2:
        return fqdn
    if parts[-2] in common_tld:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


# If it comes back, then it's a seperate corporate entity. At this point, we
# cannot say if they are related to our organization becasue we don't have
# acquisition data from Crunchbase.
def odm_lookup(domain):
    if os.path.exists('organizations.csv'):
        try:
            subprocess.check_output(['rg', '\"%s\"' % domain, 'organizations.csv'], shell=False)
        except subprocess.CalledProcessError:
            return False
    return True


def whois_lookup(tld, whois_org):
    try:
        parsed = whois.whois(tld)
        for k,v in parsed.items():
            if v and v.startswith(whois_org):
                return True
    except Exception as ex:
        print ex
    return False


def main():
    global BANNER
    global KNOWN_CA_ORGS

    parser = argparse.ArgumentParser(description="Enumerates subdomains and TLDs with x509 data")
    parser.add_argument('-s', metavar='SEED', help='x509 "Organization" or "Organizational Unit"', required=True)
    parser.add_argument('-w', metavar='WHOIS', help='WHOIS organization name for correlation', required=False)
    parser.add_argument('-o', metavar='FILE', help='optional output file', required=False)
    args = vars(parser.parse_args())

    print BANNER

    crt_sh_conn_str = 'dbname=certwatch host=crt.sh user=guest'
    conn = psycopg2.connect(crt_sh_conn_str)
    cur = conn.cursor()
    seed = args['s']
    whois_org = args['s']

    if args['w']:
        whois_org = args['w']
    
    possible_orgs = set([seed])
    raw_domains = set(get_x509_linked_tlds(cur, args['s']))
    uniq_tlds = set(filter(lambda x: not (x == ''), map(extract_tld, map(str.lower, raw_domains))))

    for tld in uniq_tlds:
        if odm_lookup(tld) and (not whois_lookup(tld, whois_org)):
            print '[!] %s belongs to another company, not using!' % tld
            continue
       
        print '[+] Looking for orgs in subdomains of %s' % tld
        org = get_tld_linked_orgs(cur, tld)
        possible_orgs |= set(filter(lambda x: not (x in KNOWN_CA_ORGS), org))

    output = {'domains': list(uniq_tlds), 'possible_orgs': list(possible_orgs)}

    if args['o']:
        try:
            with open(args['o'], 'w') as out_file:
                out_file.write(json.dumps(output))
        except Exception as ex:
            print 'Could not output to file: %s' % args['o']
            print 'Error message: %s' % ex.message
    else:
        print json.dumps(output)


if __name__ == '__main__':
    main()

