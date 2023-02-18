import re
from core.utils import resolve_multi, status_code, response_body, has_azure_verification_txt


SCOPE_PATTERNS = [
    r'\.cloudapp\.net$',
    r'\.azurewebsites\.net$',
    r"\.cloudapp.azure\.com$",
    r"\.azurewebsites\.net$",
    r"\.blob\.core\.windows\.net$",
    r"\.cloudapp\.azure\.com$",
    r"\.azure-api\.net$",
    r"\.azurehdinsight\.net$",
    r"\.azureedge\.net$",
    r"\.azurecontainer\.io$",
    r"\.database.windows\.net$",
    r"\.azuredatalakestore\.net$",
    r"\.search.windows\.net$",
    r"\.azurecr\.io$",
    r"\.redis\.cache\.windows\.net$",
    r"\.azurehdinsight\.net$",
    r"\.servicebus.windows\.net$",
    r"\.visualstudio\.com$",
    r"cname\.agilecrm\.com$",
    r"^[a-z0-9\.\-]{0,63}\.?s3.amazonaws\.com$",
    r"^[a-z0-9\.\-]{0,63}\.?s3-website[\.-](eu|ap|us|ca|sa|cn)-\w{2,14}-\d{1,2}\.amazonaws.com(\.cn)?$",
    r"^[a-z0-9\.\-]{0,63}\.?s3[\.-](eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$",
    r"^[a-z0-9\.\-]{0,63}\.?s3.dualstack\.(eu|ap|us|ca|sa)-\w{2,14}-\d{1,2}\.amazonaws.com$",
    r"^cdn\.airee\.ru$",
    r"\.wordpress\.com$",
    r"^readthedocs\.io$",
    r"^cname\.canny\.io$",
    r"\.shops\.myshopify\.com$",
    r"\.myshopify.com$"
]

FINGERPRINT_REGEX = r'(doesn\'t exist|(not|isn\'t) (find|(been )?found|(longer )?available|configured|connected)|unknown (domain|site)|claim|no longer here|unavailable)'

class TakeoverVerifier:
    def __init__(self, dns_scanner, nameservers=None,
                 use_google_dns=False, only_in_scope=True):
        self.dns_scanner = dns_scanner
        self.nameservers = nameservers
        self.use_google_dns = use_google_dns
        self.only_in_scope = only_in_scope

    def domain_takeover_factors(self, record):
        is_private = record['Private']
        record_name = record['Name']
        record_value = record['Value']
        takeover_factors = set()
        mitigation_factors = set()

        if is_private:
            mitigation_factors.add('PRIVATE_ZONE')

        records = resolve_multi(
            record_value,
            nameservers=self.nameservers,
            use_google_dns=self.use_google_dns
        )

        if not records:
            takeover_factors.add('DNS_NXDOMAIN')
        else:
            status_code_https = status_code(record_value)
            status_code_http = status_code(record_value, schema='http')
            if status_code_https == 404 or status_code_http == 404:
                takeover_factors.add('WEB_NOTFOUND')

            response_https = response_body(record_value)
            response_http = response_body(record_value, schema='http')
            fingerprint_https = re.search(FINGERPRINT_REGEX, response_https)
            fingerprint_http = re.search(FINGERPRINT_REGEX, response_http)
            if fingerprint_https or fingerprint_http:
                takeover_factors.add('WEB_FINGERPRINT')

        if has_azure_verification_txt(record_name):
            mitigation_factors.add('AZURE_VERIFICATION_TXT')

        return takeover_factors, mitigation_factors

    def get_takeover_factors(self):
        records = self.dns_scanner.fetch_records()

        for record in records:
            if record['Type'] != 'CNAME':
                continue

            record['Name'] = record['Name'].rstrip('.')
            record['Value'] = record['Value'].rstrip('.')

            if self.only_in_scope:
                in_scope = False
                for pattern in SCOPE_PATTERNS:
                    if re.search(pattern, record['Value']):
                        in_scope = True

                if not in_scope:
                    continue

            t_factors, m_factors = self.domain_takeover_factors(record)

            yield record, t_factors, m_factors
