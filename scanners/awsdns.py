import boto3


class AWSDNSScanner():
    def __init__(self):
        self.client = boto3.client('route53')

    def fetch_rrsets(self):
        zones = []
        zones_iter = self.client.get_paginator(
            'list_hosted_zones'
        )

        for zones_page in zones_iter.paginate():
            zones += zones_page['HostedZones']

        for zone in zones:
            zone_id = zone['Id']
            zone_name = zone['Name']
            private_zone = zone['Config']['PrivateZone']

            rrsets = []
            rrsets_iter = self.client.get_paginator(
                'list_resource_record_sets'
            )

            for rrsets_page in rrsets_iter.paginate(HostedZoneId=zone_id):
                rrsets += rrsets_page['ResourceRecordSets']

            yield zone_id, zone_name, private_zone, rrsets

    def fetch_records(self):
        rrsets_iter = self.fetch_rrsets()

        for zone_id, zone_name, private_zone, rrsets in rrsets_iter:
            for rrset in rrsets:
                rrset_name = rrset['Name']
                rrset_type = rrset['Type']
                if 'ResourceRecords' not in rrset:
                    continue

                for record in rrset['ResourceRecords']:
                    record_value = record['Value']
                    yield {
                        'ZoneID': zone_id,
                        'ZoneName': zone_name,
                        'Private': private_zone,
                        'Name': rrset_name,
                        'Type': rrset_type,
                        'Value': record_value
                    }
