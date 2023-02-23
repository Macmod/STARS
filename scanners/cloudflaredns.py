import CloudFlare


class CloudFlareDNSScanner():
    def __init__(self):
        self.client = CloudFlare.CloudFlare(raw=True)

    def fetch_records(self, zones_batch=5):
        page_no = 0
        total_pages = float('inf')
        while page_no < total_pages:
            page_no += 1

            raw_results = self.client.zones.get(
                params={'per_page': zones_batch, 'page': page_no}
            )
            zones = raw_results['result']

            total_pages = raw_results['result_info']['total_pages']

            for zone in zones:
                try:
                    records = self.client.zones.dns_records.get(zone['id'])
                except CloudFlare.exceptions.CloudFlareAPIError as e:
                    print(f'[-] CloudFlare API Error: {e}')

                for record in records:
                    yield {
                        'ZoneID': zone['id'],
                        'ZoneName': zone['name'],
                        'Private': None,
                        'Name': record['name'],
                        'Type': record['type'],
                        'Value': record['content']
                    }
