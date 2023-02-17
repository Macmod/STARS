from google.cloud import dns

class GCPDNSScanner():
    def __init__(self):
        self.dns_client = dns.Client()

    def fetch_records(self):
        zones = self.dns_client.list_zones()

        for zone in zones:
            records = zone.list_resource_record_sets()
            for record in records:
                for record_value in record.rrdatas:
                    yield {
                        'ZoneID': zone.zone_id,
                        'ZoneName': zone.dns_name,
                        'Private': None,
                        'Name': record.name,
                        'Type': record.record_type,
                        'Value': record_value
                    }