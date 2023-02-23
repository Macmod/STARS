import digitalocean


class DigitalOceanDNSScanner():
    def __init__(self):
        self.client = digitalocean.Manager()

    def fetch_records(self):
        domains = self.client.get_all_domains()

        for domain in domains:
            records = domain.get_records()

            for record in records:
                yield {
                    'ZoneName': domain.name,
                    'Private': None,
                    'Name': record.name,
                    'Type': record.type,
                    'Value': record.data
                }
