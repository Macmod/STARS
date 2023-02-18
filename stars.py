from azure.identity import AzureCliCredential
from scanners.awsdns import AWSDNSScanner
from scanners.azuredns import AzureDNSScanner
from scanners.gcpdns import GCPDNSScanner
from scanners.filedns import FileDNSScanner
from verifiers.takeover import TakeoverVerifier
from urllib3.exceptions import InsecureRequestWarning
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import requests
import argparse
import json
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

colorama_init()

banner = """  .-')    .-') _      ('-.     _  .-')    .-')    
 ( OO ). (  OO) )    ( OO ).-.( \( -O )  ( OO ).  
(_)---\_)/     '._   / . --. / ,------. (_)---\_) 
/    _ | |'--...__)  | \-.  \  |   /`. '/    _ |  
\  :` `. '--.  .--'.-'-'  |  | |  /  | |\  :` `.  
 '..`''.)   |  |    \| |_.'  | |  |_.' | '..`''.) 
.-._)   \   |  |     |  .-.  | |  .  '.'.-._)   \ 
\       /   |  |     |  | |  | |  |\  \ \       / 
 `-----'    `--'     `--' `--' `--' '--' `-----'  """
title = 'Subdomain Takeover - A Record Scanner'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='STARS is a multi-cloud DNS record scanner that scans the records from all DNS zones in an environment and provides a list of all CNAME domains that might be offline / possible candidates for subdomain takeover.'
    )
    parser.add_argument('--azure', action='store_true',
                        help='Scan Azure DNS services.')
    parser.add_argument('--subscription',
                        help='ID of the Azure Subscription to scan.')
    parser.add_argument('--aws', action='store_true',
                        help='Scan AWS Route53 service.')
    parser.add_argument('--gcp', action='store_true',
                        help='Scan GCP DNS service.')
    parser.add_argument('--file', help='Scan a file with a list of domains.')
    parser.add_argument('--google-dns', action='store_true',
                        help='Use Google DoH for NXDOMAIN check.')
    parser.add_argument('--nameservers',
                        help='Custom nameservers to use for NXDOMAIN check.')
    parser.add_argument('--all-records', action='store_true',
                        help='Check all records from the DNS zone, not only those in the scope.')
    parser.add_argument('--no-colors', action='store_true',
                        help='Disable colorized output.')
    parser.add_argument('--no-banners', action='store_true',
                        help='Don\'t show banners, just the results.')
    parser.add_argument('--dump', action='store_true',
                        help='Don\'t analyze anything, just dump all the records.')


    args = parser.parse_args()

    if not args.no_banners:
        print(banner)

        print()

        print(title)

        print()

    if args.azure:
        scanner = AzureDNSScanner(args.subscription)
        module = 'Azure'
        module_color = f'{Fore.BLUE}'
    elif args.aws:
        scanner = AWSDNSScanner()
        module = 'AWS'
        module_color = f'{Fore.YELLOW}'
    elif args.gcp:
        scanner = GCPDNSScanner()
        module = 'GCP'
        module_color = f'{Fore.WHITE}'
    else:
        scanner = FileDNSScanner(args.file)
        module = f'File ({args.file})'
        module_color = f'{Fore.GREEN}'

    if not args.no_banners:
        if args.no_colors:
            print(f'[+] Selected module: {module}')
        else:
            print(f'[+] Selected module: {module_color}{module}{Style.RESET_ALL}')

        print()

    result = False
    if args.dump:
        for record in scanner.fetch_records():
            print(json.dumps(record))
            if not result:
                result = True
    else:
        verifier = TakeoverVerifier(
            scanner,
            use_google_dns=args.google_dns,
            nameservers=args.nameservers.split(','),
            only_in_scope=not args.all_records
        )

        factors = verifier.get_takeover_factors()

        for record, takeover_factors, mitigation_factors in factors:
            record_name = record['Name']
            record_value = record['Value']

            takeover_factors_str = ','.join(list(takeover_factors))
            mitigation_factors_str = ','.join(list(mitigation_factors))

            if len(takeover_factors) == 0:
                continue

            if args.no_colors:
                print(f'{record_name} => {record_value} (TF: {takeover_factors_str}) (MF: {mitigation_factors_str})')
            else:
                print(f'{record_name} => {record_value} {Fore.GREEN}{takeover_factors_str}{Style.RESET_ALL} {Fore.RED}{mitigation_factors_str}{Style.RESET_ALL}')

            if not result:
                result = True

    if not result:
        print('[-] No results found.')
        print('[-] Make sure you authenticated correctly to your provider.')
