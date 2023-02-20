from scanners.awsdns import AWSDNSScanner
from scanners.azuredns import AzureDNSScanner
from scanners.gcpdns import GCPDNSScanner
from scanners.filedns import FileDNSScanner
from verifiers.takeover import TakeoverVerifier
from urllib3.exceptions import InsecureRequestWarning
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from tabulate import tabulate
from tqdm import tqdm
import requests
import argparse
import json
import sys
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
    parser.add_argument('--all-records', action='store_true',
                        help='Check all records from the DNS zone, not only those in the scope.')
    parser.add_argument('--dump-records', action='store_true',
                        help='Don\'t analyze anything, just dump all the records.')
    parser.add_argument('--no-banners', action='store_true',
                        help='Don\'t show banners, just the results.')
    parser.add_argument('--no-colors', action='store_true',
                        help='Disable colorized output.')
    parser.add_argument('--no-table', action='store_true',
                        help='Disable building results table (just show results line-by-line).')
    parser.add_argument('--output', help='Save results to a file.')
    parser.add_argument('--google-dns', action='store_true',
                        help='Use Google DoH for NXDOMAIN check.')
    parser.add_argument('--nameservers',
                        help='Custom nameservers to use for NXDOMAIN check.')

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

    output_filename = args.output
    output_file = None
    if output_filename:
        try:
            output_file = open(output_filename, 'w')
        except Exception:
            print(f'[-] Error opening file "{output_filename}"')
            sys.exit(1)

    result = False
    if args.dump_records:
        for record in scanner.fetch_records():
            record_json = json.dumps(record)
            print(record_json)

            if output_file is not None:
                output_file.write(record_json + '\n')

            if not result:
                result = True
    else:
        use_google_dns = args.google_dns
        nameservers = args.nameservers.split(',') if args.nameservers else None
        only_in_scope = not args.all_records
        verifier = TakeoverVerifier(
            scanner,
            use_google_dns=use_google_dns,
            nameservers=nameservers,
            only_in_scope=only_in_scope
        )

        factors = verifier.get_takeover_factors()

        if args.no_table:
            factors_iterator = factors
        else:
            factors_iterator = tqdm(factors)

        finding_table = []
        for record, takeover_factors, mitigation_factors in factors_iterator:
            record_name = record['Name']
            record_value = record['Value']

            takeover_factors_str = ','.join(list(takeover_factors))
            mitigation_factors_str = ','.join(list(mitigation_factors))

            if len(takeover_factors) == 0:
                continue

            if args.no_colors:
                finding_row = [
                    record_name,
                    record_value,
                    takeover_factors_str,
                    mitigation_factors_str
                ]
                finding_str = f'{record_name} => {record_value} (TF: {takeover_factors_str}) (MF: {mitigation_factors_str})'
            else:
                finding_row = [
                    record_name,
                    record_value,
                    f'{Fore.GREEN}{takeover_factors_str}{Style.RESET_ALL}',
                    f'{Fore.RED}{mitigation_factors_str}{Style.RESET_ALL}'
                ]
                finding_str = f'{record_name} => {record_value} {Fore.GREEN}{takeover_factors_str}{Style.RESET_ALL} {Fore.RED}{mitigation_factors_str}{Style.RESET_ALL}'

            if args.no_table:
                print(finding_str)
            else:
                finding_table.append(finding_row)

            if output_file is not None:
                output_file.write(finding_str + '\n')

            if not result:
                result = True

        headers = ['Name', 'Target', 'Takeover Factors', 'Mitigation Factors']
        print()
        print(tabulate(finding_table, headers=headers))

    if output_file is not None:
        output_file.close()

    if not result:
        print('[-] No results found.')
        print('[-] Make sure you authenticated correctly to your provider.')