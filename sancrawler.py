#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import re
import json

import psycopg2


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


# Query the crt.sh looking for subdomains of a given top level domain.
# Additionally, we grab the certificate's organizationalName and
# organizationalUnitName. We use those later, to look for potentially more seed
# values to use. Results are returned as a 2-tuple of ([SUBDOMAINS], [ORG-NAMES])
def get_subdomains(cur, tld):
    ret = ([], [])
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
            if record[1]:
                ret[0].append(record[1])
            if record[2]:
                ret[1].append(record[2])
            if record[3]:
                ret[1].append(record[3])
    except psycopg2.ProgrammingError as ex:
        print 'Programming error caught: '
        print str(ex)
    return ret


# Query the crt.sh postgresql instance looking for shared organizationName or
# organizationalUnitName. Return the domains/subdomains in one list as strs.
def get_linked_tlds(cur, org):
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
def get_domain_name(fqdn):
    parts = fqdn.split('.')
    if len(parts) == 1:
        return ''
    if len(parts) <= 2:
        return fqdn
    if parts[-2] == 'co' or parts[-2] == 'com':
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


# A wrapper for sorensen_dice and potentially other metrics. "Normalizes"
# data for better application of a metric prior to running it. Also in this
# case performs a "maximal" of the metric in that it uses partial matches,
# taking the maximal value of any partial match.
def run_metric(s1, s2, metric_fn):
    t1 = re.sub(r'[\.\,\"\'\(\-\;]+', '', s1).lower()
    t2 = re.sub(r'[\.\,\"\'\(\-\;]+', '', s2).lower()
    tokens_t1 = t1.split(' ')
    hi = 0
    for i in range(len(tokens_t1)):
        next_str = ''.join(tokens_t1[:i+1])
        hi = max(metric_fn(next_str, t2), hi)
    return hi


# Computes the Sørensen Dice coefficient of strings s1 and s2. It helps in
# determining a score for string similarity. String similarity preferred
# primarily for convenience, it is likely that a better solution exists for
# determining potentially linked "Organization" and "Organizational Unit"
# fields. But for now, this works OK.
def sorensen_dice(s1, s2):
    set1 = set([s1[i:i+2] for i in range(len(s1)-1)])
    set2 = set([s2[i:i+2] for i in range(len(s2)-1)])
    n_intersect = len(set1.intersection(set2))
    n_total = len(set1) + len(set2)
    return float(2 * n_intersect) / float(n_total)


def main():
    global BANNER

    # The threshold value of 0.6 is arbitrary
    parser = argparse.ArgumentParser(description="Enumerates subdomains and TLDs with x509 data")
    parser.add_argument('-t', metavar='THRESHOLD', 
                        help='Sorensen-Dice threshold (0.0, 1.0]', type=float, required=False, default=0.6)
    parser.add_argument('-s', metavar='SEED', help='x509 "Organization" or "Organizational Unit"', required=True)
    parser.add_argument('-o', metavar='FILE', help='optional output file', required=False)
    args = vars(parser.parse_args())
    threshold = args['t']

    print BANNER

    crt_sh_conn_str = 'dbname=certwatch host=crt.sh user=guest'
    conn = psycopg2.connect(crt_sh_conn_str)
    cur = conn.cursor()
    possible_orgs = set([args['s']])
    known_domains = set(get_linked_tlds(cur, args['s']))
    tlds = set(filter(lambda x: not (x == ''),
                      map(get_domain_name, known_domains)))

    print '[*] Using Sorensen-Dice threshold of %f' % threshold

    for tld in tlds:
        print '[+] Querying subdomains on %s' % tld
        sub, org = get_subdomains(cur, tld)
        known_domains |= set(sub)
        possible_orgs |= set(filter(lambda x: run_metric(x, tld, sorensen_dice) > threshold, org))

    output = {'known_domains': list(known_domains), 'possible_orgs': list(possible_orgs)}

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
